/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Reconciles backend health into the data plane's maps. Knows nothing about
 * BPF: it writes through a `sink`, so the failover ordering can be unit-tested.
 */
#ifndef LB_BALANCER_H
#define LB_BALANCER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "health.h"
#include "lb_common.h"

struct sink {
	void *ctx;
	int (*put_backend)(void *ctx, uint32_t idx, bool healthy, const uint8_t mac[6]);
	int (*put_slot)(void *ctx, uint32_t slot, uint32_t value);
};

struct bal_backend {
	uint32_t ip_be;		/* network byte order */
	uint16_t port;		/* host byte order */
	bool     has_mac;	/* static MAC configured; otherwise learned from ARP */
	uint8_t  mac[6];
};

struct probe_result {
	bool    ok;		/* TCP connect succeeded */
	bool    mac_known;
	uint8_t mac[6];		/* valid if mac_known */
};

struct balancer {
	size_t n;
	struct sink sink;
	struct bal_backend spec[LB_MAX_BACKENDS];
	struct health health[LB_MAX_BACKENDS];
	uint8_t mac[LB_MAX_BACKENDS][6];
	bool have_mac[LB_MAX_BACKENDS];
	struct {
		bool    healthy;
		uint8_t mac[6];
	} written[LB_MAX_BACKENDS];	/* what the data plane currently holds */
	uint32_t table[LB_TABLE_SIZE];	/* shadow of lookup_table */
	bool table_up[LB_MAX_BACKENDS];	/* backends the table was built from */
};

/* Assumes the data plane starts zeroed: all backends unhealthy. */
int  balancer_init(struct balancer *b, const struct bal_backend *spec, size_t n,
		   int rise, int fall, struct sink sink);
/* Mark every slot empty (array maps start zeroed, which would mean "backend 0"). */
int  balancer_reset_table(struct balancer *b);
/* One probe round: res[0..n). Returns 0, or -1 if any map write failed (retried next round). */
int  balancer_apply(struct balancer *b, const struct probe_result *res);

#endif
