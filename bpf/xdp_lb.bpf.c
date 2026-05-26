// SPDX-License-Identifier: GPL-2.0
/*
 * XDP load balancer, L2 Direct Server Return.
 *
 * Packets addressed to the VIP are hashed on their 5-tuple, mapped to a
 * backend through a Maglev lookup table, and bounced back out of the same
 * interface with only the Ethernet header rewritten. The IP header is left
 * alone, so backends (which hold the VIP on a loopback alias) answer the
 * client directly and replies never touch the LB.
 *
 * Per-packet cost is kept low on purpose:
 *  - VIP, LB MAC and the flow-cache switch are .rodata, set once before load.
 *    The verifier folds them into constants and drops the flow-cache code
 *    entirely when it is disabled.
 *  - All global counters live in one per-CPU struct, so a packet does one
 *    stats lookup (plus one for its backend) instead of one per counter.
 *
 * What changes at runtime, via the control plane: `backends` (MAC + health)
 * and `lookup_table` (Maglev slots). The program is never reloaded.
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "lb_common.h"

/* linux/stddef.h defines a non-forcing __always_inline */
#undef __always_inline
#define __always_inline inline __attribute__((always_inline))

#define IP_MF     0x2000
#define IP_OFFSET 0x1fff

const volatile __be32 cfg_vip;
const volatile __u32  cfg_mac_hi;	/* first 4 bytes of the LB MAC (memcpy order) */
const volatile __u16  cfg_mac_lo;	/* last 2 bytes */
const volatile __u8   cfg_flow_cache;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, LB_MAX_BACKENDS);
	__type(key, __u32);
	__type(value, struct backend);
} backends SEC(".maps");

/* Maglev table: slot -> backend index (LB_NO_BACKEND when empty). */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, LB_TABLE_SIZE);
	__type(key, __u32);
	__type(value, __u32);
} lookup_table SEC(".maps");

/* Pins established flows so table changes don't remap them. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, LB_FLOW_CACHE_MAX);
	__type(key, struct flow_key);
	__type(value, __u32);
} flow_cache SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct lb_stats);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, LB_MAX_BACKENDS);
	__type(key, __u32);
	__type(value, struct be_stats);
} backend_stats SEC(".maps");

#define rol32(x, r) (((x) << (r)) | ((x) >> (32 - (r))))

/* Jenkins lookup3 final mix over the five tuple fields. */
static __always_inline __u32 hash_flow(const struct flow_key *k)
{
	__u32 a = 0xdeadbeef + k->proto + 20;
	__u32 b = a + k->saddr;
	__u32 c = a + k->daddr;

	a += ((__u32)k->sport << 16) | k->dport;

	c ^= b; c -= rol32(b, 14);
	a ^= c; a -= rol32(c, 11);
	b ^= a; b -= rol32(a, 25);
	c ^= b; c -= rol32(b, 16);
	a ^= c; a -= rol32(c, 4);
	b ^= a; b -= rol32(a, 14);
	c ^= b; c -= rol32(b, 24);
	return c;
}

/* Only frames actually sent to us; a bridge may flood others our way. */
static __always_inline int to_lb_mac(const struct ethhdr *eth)
{
	__u32 hi;
	__u16 lo;

	__builtin_memcpy(&hi, eth->h_dest, sizeof(hi));
	__builtin_memcpy(&lo, eth->h_dest + 4, sizeof(lo));
	return hi == cfg_mac_hi && lo == cfg_mac_lo;
}

SEC("xdp")
int xdp_lb(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct flow_key fk = {};
	struct backend *be = NULL;
	struct be_stats *bs;
	struct lb_stats *st;
	struct iphdr *ip;
	__u32 zero = 0, idx = LB_NO_BACKEND;
	__u64 len = data_end - data;

	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end || ip->ihl < 5)
		return XDP_PASS;
	if (ip->daddr != cfg_vip)
		return XDP_PASS;
	if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
		return XDP_PASS;
	if (!to_lb_mac(eth))
		return XDP_PASS;

	fk.saddr = ip->saddr;
	fk.daddr = ip->daddr;
	fk.proto = ip->protocol;

	/*
	 * Fragments after the first carry no L4 header, so hash every fragment
	 * of a datagram on the 3-tuple to keep them on one backend.
	 */
	if (!(ip->frag_off & bpf_htons(IP_MF | IP_OFFSET))) {
		const __be16 *ports = (void *)ip + ip->ihl * 4;

		if ((void *)(ports + 2) > data_end)
			return XDP_PASS;
		fk.sport = ports[0];
		fk.dport = ports[1];
	}

	st = bpf_map_lookup_elem(&stats, &zero);
	if (!st)
		return XDP_PASS;
	st->rx_vip++;

	if (cfg_flow_cache) {
		__u32 *cached = bpf_map_lookup_elem(&flow_cache, &fk);

		if (cached) {
			idx = *cached;
			be = bpf_map_lookup_elem(&backends, &idx);
			if (be && be->healthy)
				st->flow_hits++;
			else
				be = NULL;
		}
	}

	if (!be) {
		__u32 slot = hash_flow(&fk) % LB_TABLE_SIZE;
		__u32 *entry = bpf_map_lookup_elem(&lookup_table, &slot);

		if (entry) {
			idx = *entry;
			be = bpf_map_lookup_elem(&backends, &idx);
		}
		if (!be || !be->healthy) {
			st->no_backend++;
			return XDP_DROP;
		}
		if (cfg_flow_cache)
			bpf_map_update_elem(&flow_cache, &fk, &idx, BPF_ANY);
	}

	/* L2 DSR: only the Ethernet header changes, IP/L4 checksums stay valid. */
	__builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, be->mac, ETH_ALEN);

	st->forwarded++;
	st->bytes += len;

	bs = bpf_map_lookup_elem(&backend_stats, &idx);
	if (bs) {
		bs->packets++;
		bs->bytes += len;
	}
	return XDP_TX;
}

char _license[] SEC("license") = "GPL";
