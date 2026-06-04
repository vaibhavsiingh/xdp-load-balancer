/* SPDX-License-Identifier: GPL-2.0 */
#ifndef LB_HEALTH_H
#define LB_HEALTH_H

#include <stdbool.h>

/*
 * Debounced up/down state: `rise` consecutive successes to come up, `fall`
 * consecutive failures to go down. Starts down.
 */
struct health {
	bool up;
	int streak;
	int rise, fall;
};

static inline void health_init(struct health *h, int rise, int fall)
{
	h->up = false;
	h->streak = 0;
	h->rise = rise;
	h->fall = fall;
}

/* Feed one probe result; returns true if the state flipped. */
static inline bool health_record(struct health *h, bool ok)
{
	if (ok == h->up) {
		h->streak = 0;
		return false;
	}
	if (++h->streak >= (ok ? h->rise : h->fall)) {
		h->up = ok;
		h->streak = 0;
		return true;
	}
	return false;
}

#endif
