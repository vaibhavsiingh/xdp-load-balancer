// SPDX-License-Identifier: GPL-2.0
/*
 * Isolated per-packet cost of the XDP program, via BPF_PROG_TEST_RUN.
 *
 * The kernel runs the program `repeat` times back-to-back on a crafted packet
 * and reports total_time / repeat, so there is no veth, bridge, driver or
 * per-packet timer in the number. It is a warm-cache figure: the lower bound.
 * The `scripts/bench.py` figure (live traffic, bpf_stats) is the cold-cache,
 * higher one. Needs root.
 *
 * Test-run repeats on one buffer, so the rewrite must be idempotent: every
 * backend MAC is set equal to the LB MAC, so a rewritten packet still matches.
 *
 *   sudo build/bench_prog [--flows N] [--repeat R] [--rounds K] [--cache on|off]
 *                         [--backends B] [--cpu C]
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lb_common.h"
#include "maglev.h"
#include "xdp_lb.skel.h"

#define PKT_LEN 64
#define XDP_PASS_RET 2
#define XDP_TX_RET 3

static const uint8_t LB_MAC[6] = {0x02, 0, 0, 0, 0, 0x01};
static const uint32_t VIP_HOST = 0x0a000064;		/* 10.0.0.100 */

static void build_pkt(uint8_t *buf, uint32_t daddr_host, uint16_t sport)
{
	struct ethhdr *eth = (void *)buf;
	struct iphdr *ip = (void *)(eth + 1);
	struct udphdr *udp = (void *)(ip + 1);

	memset(buf, 0, PKT_LEN);
	memcpy(eth->h_dest, LB_MAC, 6);
	memcpy(eth->h_source, "\x02\0\0\0\0\x02", 6);
	eth->h_proto = htons(ETH_P_IP);
	ip->version = 4;
	ip->ihl = 5;
	ip->tot_len = htons(PKT_LEN - sizeof(*eth));
	ip->ttl = 64;
	ip->protocol = IPPROTO_UDP;
	ip->saddr = htonl(0x0a000002);
	ip->daddr = htonl(daddr_host);
	udp->source = htons(sport);
	udp->dest = htons(9);
	udp->len = htons(PKT_LEN - sizeof(*eth) - sizeof(*ip));
}

/* Mean ns/packet over all flows; each flow's packet is run `repeat` times. */
static double sweep(int prog_fd, uint32_t daddr_host, int flows, int repeat, uint32_t want_ret)
{
	uint8_t pkt[PKT_LEN];
	double sum = 0;

	for (int f = 0; f < flows; f++) {
		LIBBPF_OPTS(bpf_test_run_opts, o, .data_in = pkt, .data_size_in = PKT_LEN,
			    .repeat = repeat);

		build_pkt(pkt, daddr_host, 1024 + f);
		if (bpf_prog_test_run_opts(prog_fd, &o)) {
			perror("bpf_prog_test_run_opts");
			exit(1);
		}
		if (o.retval != want_ret) {
			fprintf(stderr, "unexpected verdict %u (wanted %u) for flow %d\n", o.retval, want_ret, f);
			exit(1);
		}
		sum += o.duration;
	}
	return sum / flows;
}

static int cmp_double(const void *a, const void *b)
{
	double x = *(const double *)a, y = *(const double *)b;

	return (x > y) - (x < y);
}

static double median(double *v, int n)
{
	qsort(v, n, sizeof(*v), cmp_double);
	return v[n / 2];
}

static int quiet(enum libbpf_print_level l, const char *fmt, va_list ap)
{
	return l == LIBBPF_DEBUG ? 0 : vfprintf(stderr, fmt, ap);
}

int main(int argc, char **argv)
{
	int flows = 1024, repeat = 20000, rounds = 7, nb = 3, cpu = -1;
	bool cache = true;
	double vip[64], floor_[64];
	struct xdp_lb_bpf *skel;
	uint32_t ids[LB_MAX_BACKENDS], table[LB_TABLE_SIZE];
	uint64_t keys[LB_MAX_BACKENDS];

	for (int i = 1; i < argc; i++) {
		if (i + 1 >= argc)
			goto usage;
		if (!strcmp(argv[i], "--flows"))
			flows = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--repeat"))
			repeat = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--rounds"))
			rounds = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--backends"))
			nb = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--cpu"))
			cpu = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--cache"))
			cache = strcmp(argv[++i], "off") != 0;
		else
			goto usage;
	}
	if (flows < 1 || flows > 60000 || repeat < 1 || rounds < 1 || rounds > 64 ||
	    nb < 1 || nb > LB_MAX_BACKENDS)
		goto usage;

	if (cpu >= 0) {
		cpu_set_t set;

		CPU_ZERO(&set);
		CPU_SET(cpu, &set);
		if (sched_setaffinity(0, sizeof(set), &set) < 0)
			perror("sched_setaffinity");
	}

	libbpf_set_print(quiet);
	skel = xdp_lb_bpf__open();
	if (!skel)
		return 1;
	skel->rodata->cfg_vip = htonl(VIP_HOST);
	skel->rodata->cfg_flow_cache = cache;
	memcpy(&skel->rodata->cfg_mac_hi, LB_MAC, 4);
	memcpy(&skel->rodata->cfg_mac_lo, LB_MAC + 4, 2);
	if (xdp_lb_bpf__load(skel)) {
		fprintf(stderr, "load failed (need root?)\n");
		return 1;
	}

	for (int i = 0; i < nb; i++) {
		struct backend be = {.healthy = 1};
		uint32_t k = i;

		memcpy(be.mac, LB_MAC, 6);	/* == LB MAC: keeps the repeated rewrite idempotent */
		bpf_map_update_elem(bpf_map__fd(skel->maps.backends), &k, &be, BPF_ANY);
		ids[i] = i;
		keys[i] = 0x0a00000b + i;
	}
	if (maglev_build(table, LB_TABLE_SIZE, ids, keys, nb) < 0)
		return 1;
	for (uint32_t s = 0; s < LB_TABLE_SIZE; s++)
		bpf_map_update_elem(bpf_map__fd(skel->maps.lookup_table), &s, &table[s], BPF_ANY);

	int fd = bpf_program__fd(skel->progs.xdp_lb);

	sweep(fd, VIP_HOST, flows, repeat / 10 + 1, XDP_TX_RET);	/* warm-up; fills the cache */
	for (int r = 0; r < rounds; r++) {
		vip[r] = sweep(fd, VIP_HOST, flows, repeat, XDP_TX_RET);
		floor_[r] = sweep(fd, VIP_HOST + 1, flows, repeat, XDP_PASS_RET);
	}

	double vmin = vip[0], fmin = floor_[0];

	for (int r = 1; r < rounds; r++) {
		vmin = vip[r] < vmin ? vip[r] : vmin;
		fmin = floor_[r] < fmin ? floor_[r] : fmin;
	}
	double vmed = median(vip, rounds), fmed = median(floor_, rounds);

	printf("BPF_PROG_TEST_RUN: %d flows x %d reps, %d rounds, %d backends, flow cache %s\n",
	       flows, repeat, rounds, nb, cache ? "on" : "off");
	printf("  forward path (VIP -> XDP_TX)      median %6.1f ns   min %6.1f ns\n", vmed, vmin);
	printf("  floor (non-VIP, early XDP_PASS)   median %6.1f ns   min %6.1f ns\n", fmed, fmin);
	printf("  attributable to balancing         median %6.1f ns\n", vmed - fmed);
	xdp_lb_bpf__destroy(skel);
	return 0;

usage:
	fprintf(stderr, "usage: bench_prog [--flows N] [--repeat R] [--rounds K] [--cache on|off] "
			"[--backends B] [--cpu C]\n");
	return 2;
}
