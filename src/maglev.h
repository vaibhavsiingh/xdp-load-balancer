/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Maglev consistent hashing (Eisenbud et al., NSDI '16): builds the
 * slot -> backend table the XDP program indexes with its flow hash.
 * Removing a backend reassigns (roughly) only the slots it owned.
 */
#ifndef LB_MAGLEV_H
#define LB_MAGLEV_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool maglev_is_prime(uint32_t n);

/*
 * Fill table[0..size) from n backends. ids[k] is the value stored for backend
 * k (LB_NO_BACKEND is reserved for "empty"); keys[k] is a stable identity that
 * seeds its permutation, so a backend keeps its preferences as others come
 * and go. size must be prime. Returns 0, or -1 on bad arguments.
 */
int maglev_build(uint32_t *table, uint32_t size, const uint32_t *ids,
		 const uint64_t *keys, size_t n);

#endif
