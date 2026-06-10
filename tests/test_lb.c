// SPDX-License-Identifier: GPL-2.0
// Unit tests for the pure logic: Maglev, health debouncing, reconciliation.
#include <stdio.h>
#include <string.h>

#include "balancer.h"
#include "maglev.h"

static int failures, checks;

#define CHECK(cond) do { \
	checks++; \
	if (!(cond)) { failures++; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } \
} while (0)

/* Whole-table predicates, so each scenario counts as one check. */
static bool table_all(const uint32_t *t, uint32_t v)
{
	for (int s = 0; s < LB_TABLE_SIZE; s++)
		if (t[s] != v)
			return false;
	return true;
}

static bool table_all_below(const uint32_t *t, uint32_t n)
{
	for (int s = 0; s < LB_TABLE_SIZE; s++)
		if (t[s] >= n)
			return false;
	return true;
}

static bool table_none(const uint32_t *t, uint32_t v)
{
	for (int s = 0; s < LB_TABLE_SIZE; s++)
		if (t[s] == v)
			return false;
	return true;
}

/* -- maglev --------------------------------------------------------------- */

static void make_ids(uint32_t *ids, uint64_t *keys, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		ids[i] = i;
		keys[i] = 0x0a00000a + i;
	}
}

static void test_maglev(void)
{
	uint32_t ids[5], t[LB_TABLE_SIZE], t2[LB_TABLE_SIZE], cnt[5] = {0};
	uint64_t keys[5];

	CHECK(maglev_is_prime(LB_TABLE_SIZE));
	CHECK(!maglev_is_prime(4095));
	make_ids(ids, keys, 5);

	CHECK(maglev_build(t, 4096, ids, keys, 5) < 0);	/* not prime */

	CHECK(maglev_build(t, LB_TABLE_SIZE, ids, keys, 0) == 0);
	CHECK(table_all(t, LB_NO_BACKEND));

	CHECK(maglev_build(t, LB_TABLE_SIZE, ids, keys, 5) == 0);
	CHECK(maglev_build(t2, LB_TABLE_SIZE, ids, keys, 5) == 0);
	CHECK(!memcmp(t, t2, sizeof(t)));			/* deterministic */
	CHECK(table_all_below(t, 5));				/* every slot filled */
	for (int s = 0; s < LB_TABLE_SIZE; s++)
		cnt[t[s] < 5 ? t[s] : 0]++;
	uint32_t lo = cnt[0], hi = cnt[0];
	for (int i = 1; i < 5; i++) {
		lo = cnt[i] < lo ? cnt[i] : lo;
		hi = cnt[i] > hi ? cnt[i] : hi;
	}
	CHECK(hi - lo <= 5);					/* even spread */

	/* Remove backend 2: survivors' slots should barely move. */
	uint32_t ids4[4] = {0, 1, 3, 4};
	uint64_t keys4[4] = {keys[0], keys[1], keys[3], keys[4]};
	CHECK(maglev_build(t2, LB_TABLE_SIZE, ids4, keys4, 4) == 0);
	int moved = 0;
	CHECK(table_none(t2, 2));
	for (int s = 0; s < LB_TABLE_SIZE; s++)
		if (t[s] != 2 && t2[s] != t[s])
			moved++;
	CHECK(moved * 10 < LB_TABLE_SIZE);			/* < 10% */

	uint32_t one = 3;
	uint64_t onek = 7;
	CHECK(maglev_build(t, LB_TABLE_SIZE, &one, &onek, 1) == 0);
	CHECK(table_all(t, 3));
}

/* -- health --------------------------------------------------------------- */

static void test_health(void)
{
	struct health h;

	health_init(&h, 2, 3);
	CHECK(!health_record(&h, true) && !h.up);
	CHECK(health_record(&h, true) && h.up);
	CHECK(!health_record(&h, false) && !health_record(&h, false) && h.up);
	CHECK(health_record(&h, false) && !h.up);

	health_init(&h, 2, 2);			/* a blip resets the streak */
	health_record(&h, true);
	health_record(&h, false);
	health_record(&h, true);
	CHECK(!h.up);
}

/* -- balancer ------------------------------------------------------------- */

struct op {
	enum { PUT_BACKEND, PUT_SLOT } kind;
	uint32_t idx;		/* backend index or slot */
	uint32_t val;		/* healthy flag or slot value */
};

#define MAX_OPS 20000
static struct op ops[MAX_OPS];
static int nops;
static uint8_t last_mac[LB_MAX_BACKENDS][6];

static int fake_put_backend(void *ctx, uint32_t idx, bool healthy, const uint8_t mac[6])
{
	(void)ctx;
	if (nops < MAX_OPS)
		ops[nops++] = (struct op){PUT_BACKEND, idx, healthy};
	memcpy(last_mac[idx], mac, 6);
	return 0;
}

static int fake_put_slot(void *ctx, uint32_t slot, uint32_t value)
{
	(void)ctx;
	if (nops < MAX_OPS)
		ops[nops++] = (struct op){PUT_SLOT, slot, value};
	return 0;
}

static struct balancer bal;

static void setup(size_t n, int rise, int fall)
{
	struct bal_backend spec[8] = {0};
	struct sink sink = {NULL, fake_put_backend, fake_put_slot};

	for (size_t i = 0; i < n; i++) {
		spec[i].ip_be = 0x0a00000b + i;	/* arbitrary identities */
		spec[i].port = 80;
		spec[i].has_mac = true;
		memset(spec[i].mac, 0x10 + i, 6);
	}
	CHECK(balancer_init(&bal, spec, n, rise, fall, sink) == 0);
	CHECK(balancer_reset_table(&bal) == 0);
	nops = 0;
}

static void round_of(size_t n, const bool *ok)
{
	struct probe_result res[8] = {0};

	for (size_t i = 0; i < n; i++)
		res[i].ok = ok[i];
	CHECK(balancer_apply(&bal, res) == 0);
}

static int count_ops(int kind)
{
	int c = 0;

	for (int i = 0; i < nops; i++)
		c += (int)ops[i].kind == kind;
	return c;
}

static void test_balancer(void)
{
	const bool all_up[2] = {true, true}, one_down[2] = {true, false};

	/* join the table only after `rise` successes */
	setup(2, 2, 2);
	round_of(2, all_up);
	CHECK(nops == 0);
	round_of(2, all_up);
	CHECK(bal.table_up[0] && bal.table_up[1]);
	CHECK(count_ops(PUT_BACKEND) == 2);
	CHECK(last_mac[1][0] == 0x11);

	/* bring-up order: every backend write precedes every slot write */
	int last_backend = -1, first_slot = -1;
	for (int i = 0; i < nops; i++) {
		if (ops[i].kind == PUT_BACKEND)
			last_backend = i;
		else if (first_slot < 0)
			first_slot = i;
	}
	CHECK(last_backend < first_slot);

	/* steady state writes nothing */
	nops = 0;
	round_of(2, all_up);
	CHECK(nops == 0);

	/* one failure is tolerated; the second takes it out */
	round_of(2, one_down);
	CHECK(nops == 0);
	round_of(2, one_down);
	CHECK(!bal.table_up[1]);
	CHECK(table_all(bal.table, 0));

	/* take-down order: slot writes precede clearing the healthy flag */
	int last_slot = -1, down_flag = -1;
	for (int i = 0; i < nops; i++) {
		if (ops[i].kind == PUT_SLOT)
			last_slot = i;
		else if (ops[i].idx == 1 && ops[i].val == 0)
			down_flag = i;
	}
	CHECK(down_flag >= 0 && last_slot >= 0 && last_slot < down_flag);

	/* only changed slots are rewritten: a third of the table */
	CHECK(count_ops(PUT_SLOT) > 0 && count_ops(PUT_SLOT) < LB_TABLE_SIZE);

	/* all down -> table empty again */
	const bool none[2] = {false, false};
	round_of(2, none);
	round_of(2, none);
	CHECK(table_all(bal.table, LB_NO_BACKEND));
}

static void test_learned_mac(void)
{
	struct bal_backend spec[1] = {{.ip_be = 1, .port = 80}};
	struct sink sink = {NULL, fake_put_backend, fake_put_slot};
	struct probe_result r = {.ok = true};

	CHECK(balancer_init(&bal, spec, 1, 1, 1, sink) == 0);
	CHECK(balancer_reset_table(&bal) == 0);
	nops = 0;

	CHECK(balancer_apply(&bal, &r) == 0);		/* up, but MAC unknown: stays down */
	CHECK(!bal.health[0].up && nops == 0);

	r.mac_known = true;
	memset(r.mac, 0xab, 6);
	CHECK(balancer_apply(&bal, &r) == 0);
	CHECK(bal.health[0].up && last_mac[0][0] == 0xab);
}

int main(void)
{
	test_maglev();
	test_health();
	test_balancer();
	test_learned_mac();
	printf("%d checks, %d failed\n", checks, failures);
	return failures ? 1 : 0;
}
