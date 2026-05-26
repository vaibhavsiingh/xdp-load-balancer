/* SPDX-License-Identifier: GPL-2.0 */
/* Layouts shared by the XDP data plane and the userspace control plane. */
#ifndef LB_COMMON_H
#define LB_COMMON_H

#include <linux/types.h>

#define LB_MAX_BACKENDS   256
/* Must be prime (Maglev). */
#define LB_TABLE_SIZE     4093
#define LB_FLOW_CACHE_MAX (1 << 18)
#define LB_NO_BACKEND     0xFFFFFFFFu

/* backends[i] */
struct backend {
	__u8 mac[6];
	__u8 healthy;
	__u8 pad;
};

/* flow_cache key -- 16 bytes, no implicit padding */
struct flow_key {
	__be32 saddr;
	__be32 daddr;
	__be16 sport;
	__be16 dport;
	__u8   proto;
	__u8   pad[3];
};

/* stats[0], per CPU. One lookup per packet covers all global counters. */
struct lb_stats {
	__u64 rx_vip;		/* IPv4 TCP/UDP packets addressed to the VIP */
	__u64 forwarded;	/* rewritten and sent with XDP_TX */
	__u64 flow_hits;	/* backend taken from the flow cache */
	__u64 no_backend;	/* dropped: no healthy backend */
	__u64 bytes;		/* bytes forwarded */
};

/* backend_stats[i], per CPU */
struct be_stats {
	__u64 packets;
	__u64 bytes;
};

#endif /* LB_COMMON_H */
