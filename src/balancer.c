// SPDX-License-Identifier: GPL-2.0
#include <arpa/inet.h>
#include <string.h>

#include "balancer.h"
#include "log.h"
#include "maglev.h"

static void name_of(const struct balancer *b, size_t i, char *buf, size_t len)
{
	char ip[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &b->spec[i].ip_be, ip, sizeof(ip));
	snprintf(buf, len, "%s:%u", ip, b->spec[i].port);
}

int balancer_init(struct balancer *b, const struct bal_backend *spec, size_t n,
		  int rise, int fall, struct sink sink)
{
	if (n == 0 || n > LB_MAX_BACKENDS)
		return -1;
	memset(b, 0, sizeof(*b));
	b->n = n;
	b->sink = sink;
	for (size_t i = 0; i < n; i++) {
		b->spec[i] = spec[i];
		health_init(&b->health[i], rise, fall);
		if (spec[i].has_mac) {
			memcpy(b->mac[i], spec[i].mac, 6);
			b->have_mac[i] = true;
		}
	}
	for (uint32_t s = 0; s < LB_TABLE_SIZE; s++)
		b->table[s] = 0;	/* matches the zeroed map until reset_table() */
	return 0;
}

int balancer_reset_table(struct balancer *b)
{
	for (uint32_t s = 0; s < LB_TABLE_SIZE; s++) {
		if (b->sink.put_slot(b->sink.ctx, s, LB_NO_BACKEND) < 0)
			return -1;
		b->table[s] = LB_NO_BACKEND;
	}
	return 0;
}

static int write_backend_up(struct balancer *b, size_t i)
{
	if (b->written[i].healthy && !memcmp(b->written[i].mac, b->mac[i], 6))
		return 0;
	if (b->sink.put_backend(b->sink.ctx, i, true, b->mac[i]) < 0)
		return -1;
	b->written[i].healthy = true;
	memcpy(b->written[i].mac, b->mac[i], 6);
	return 0;
}

static int write_backend_down(struct balancer *b, size_t i)
{
	if (!b->written[i].healthy)
		return 0;
	if (b->sink.put_backend(b->sink.ctx, i, false, b->written[i].mac) < 0)
		return -1;
	b->written[i].healthy = false;
	return 0;
}

static int write_table(struct balancer *b, const bool *up)
{
	uint32_t ids[LB_MAX_BACKENDS], fresh[LB_TABLE_SIZE], changed = 0;
	uint64_t keys[LB_MAX_BACKENDS];
	size_t k = 0;

	for (size_t i = 0; i < b->n; i++) {
		if (!up[i])
			continue;
		ids[k] = i;
		keys[k] = ((uint64_t)b->spec[i].ip_be << 16) | b->spec[i].port;
		k++;
	}
	if (maglev_build(fresh, LB_TABLE_SIZE, ids, keys, k) < 0)
		return -1;
	for (uint32_t s = 0; s < LB_TABLE_SIZE; s++) {
		if (fresh[s] == b->table[s])
			continue;
		if (b->sink.put_slot(b->sink.ctx, s, fresh[s]) < 0)
			return -1;
		b->table[s] = fresh[s];
		changed++;
	}
	LOG_INFO("lookup table: %u/%u slots updated, %zu healthy backend(s)",
		 changed, (unsigned)LB_TABLE_SIZE, k);
	memcpy(b->table_up, up, b->n * sizeof(bool));
	return 0;
}

int balancer_apply(struct balancer *b, const struct probe_result *res)
{
	bool up[LB_MAX_BACKENDS], table_stale = false;
	int rc = 0;

	for (size_t i = 0; i < b->n; i++) {
		bool ok;

		if (res[i].mac_known && !b->spec[i].has_mac) {
			memcpy(b->mac[i], res[i].mac, 6);
			b->have_mac[i] = true;
		}
		ok = res[i].ok && b->have_mac[i];
		if (health_record(&b->health[i], ok)) {
			char name[32];

			name_of(b, i, name, sizeof(name));
			LOG_INFO("backend %s is %s", name, b->health[i].up ? "UP" : "DOWN");
		}
		up[i] = b->health[i].up;
		table_stale |= up[i] != b->table_up[i];
	}

	/*
	 * Bring-up: backend entry first, then the table that references it.
	 * Take-down: table first, then clear the flag, so new flows never land
	 * on a backend that is about to be marked unhealthy.
	 */
	for (size_t i = 0; i < b->n; i++)
		if (up[i] && write_backend_up(b, i) < 0)
			rc = -1;
	if (table_stale && write_table(b, up) < 0)
		rc = -1;
	for (size_t i = 0; i < b->n; i++)
		if (!up[i] && write_backend_down(b, i) < 0)
			rc = -1;
	return rc;
}
