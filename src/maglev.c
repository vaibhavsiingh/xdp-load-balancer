// SPDX-License-Identifier: GPL-2.0
#include "maglev.h"
#include "lb_common.h"

bool maglev_is_prime(uint32_t n)
{
	if (n < 2)
		return false;
	for (uint32_t i = 2; (uint64_t)i * i <= n; i++)
		if (n % i == 0)
			return false;
	return true;
}

/* splitmix64 finaliser */
static uint64_t mix64(uint64_t x)
{
	x += 0x9e3779b97f4a7c15ull;
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ull;
	x = (x ^ (x >> 27)) * 0x94d049bb133111ebull;
	return x ^ (x >> 31);
}

int maglev_build(uint32_t *table, uint32_t size, const uint32_t *ids,
		 const uint64_t *keys, size_t n)
{
	uint32_t offset[LB_MAX_BACKENDS], skip[LB_MAX_BACKENDS], next[LB_MAX_BACKENDS];
	uint32_t filled = 0;

	if (size < 3 || !maglev_is_prime(size) || n > LB_MAX_BACKENDS)
		return -1;
	for (uint32_t s = 0; s < size; s++)
		table[s] = LB_NO_BACKEND;
	if (n == 0)
		return 0;

	for (size_t k = 0; k < n; k++) {
		if (ids[k] == LB_NO_BACKEND)
			return -1;
		offset[k] = mix64(keys[k] ^ 0x6f666673ull) % size;
		skip[k] = mix64(keys[k] ^ 0x736b6970ull) % (size - 1) + 1;
		next[k] = 0;
	}

	for (;;) {
		for (size_t k = 0; k < n; k++) {
			uint32_t slot;

			do {
				slot = ((uint64_t)offset[k] + (uint64_t)next[k] * skip[k]) % size;
				next[k]++;
			} while (table[slot] != LB_NO_BACKEND);
			table[slot] = ids[k];
			if (++filled == size)
				return 0;
		}
	}
}
