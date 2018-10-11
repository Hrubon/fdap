#include "socket.h"
#include "timeout.h"
#include <assert.h>
#include <stdbool.h>
#include <time.h>

#define TOS_PER_BLOCK	256

const char *strto(enum to_type type)
{
	switch (type) {
	case TO_IDLE:
		return "idle time-out";
	case TO_RX:
		return "RX time-out";
	case TO_TX:
		return "TX time-out";
	case TO_DOWN:
		return "time to go down";
	default:
		assert(0);
	}
}

void toset_init(struct toset *set)
{
	objpool_init(&set->to_pool, sizeof(struct to), TOS_PER_BLOCK);
	for (size_t type = 0; type < TO_TYPE_MAX; type++) {
		list_init(&set->tos[type]);
		set->expiry[type] = EXPIRY_NONE;
	}
}

void toset_free(struct toset *set)
{
	objpool_free(&set->to_pool);
}

void toset_set_expiry(struct toset *set, enum to_type type, expiry_t ms)
{
	assert(ms != EXPIRY_NONE);
	set->expiry[type] = ms;
}

/*
 * Convert nanoseconds to milliseconds.
 */
static uint16_t ns_to_ms(uint64_t ns)
{
	return ns / 1e6;
}

/*
 * Return the number of milliseconds for the time-out `to` to expire since `s`.
 * If `to` expired in the past, 0 is returned.
 */
static expiry_t ms_to_expire(struct to *to, struct timespec *s)
{
	int64_t ms = 1000 * (to->exp_s - s->tv_sec) + to->exp_ms - ns_to_ms(s->tv_nsec);
	assert(ms <= EXPIRY_MAX);
	return MAX(0, ms);
}

/*
 * Is the time-out `to` expired at the time `at`?
 */
static bool expired(struct to *to, struct timespec *at)
{
	return ms_to_expire(to, at) == 0;
}

void toset_reset(struct toset *set, struct socket *socket, enum to_type type)
{
	if (set->expiry[type] == EXPIRY_NONE)
		return; /* time-out not configured */
	struct to *to = socket->tos[type];
	if (!to) {
		to = objpool_alloc(&set->to_pool);
		to->socket = socket;
		to->type = type;
		socket->tos[type] = to;
	} else {
		list_remove(&set->tos[type], &to->n);
	}
	list_insert(&set->tos[type], &to->n);
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	uint32_t ms = set->expiry[type] + ns_to_ms(now.tv_nsec);
	to->exp_s = now.tv_sec + (ms / 1000);
	to->exp_ms = ms % 1000;
}

/*
 * Cancel the time-out `to` and free the `to` structure.
 */
static void cancel(struct toset *set, struct to *to)
{
	list_remove(&set->tos[to->type], &to->n);
	to->socket->tos[to->type] = NULL;
	objpool_dealloc(&set->to_pool, &to->n);
}

void toset_cancel(struct toset *set, struct socket *socket, enum to_type type)
{
	if (socket->tos[type])
		cancel(set, socket->tos[type]);
}

void toset_cancel_all(struct toset *set, struct socket *socket)
{
	for (size_t type = 0; type < TO_TYPE_MAX; type++)
		toset_cancel(set, socket, type);
}

/*
 * Return the nearest time-out of type `type` in `set`.
 */
static struct to *nearest_to(struct toset *set, enum to_type type)
{
	struct lnode *n = list_first(&set->tos[type]);
	if (n)
		return container_of(n, struct to, n);
	return NULL;
}

void toset_check_expired(struct toset *set)
{
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	for (size_t type = 0; type < TO_TYPE_MAX; type++) {
		struct to *to;
		while ((to = nearest_to(set, type)) != NULL && expired(to, &now)) {
			to->socket->ops->timeout(to->socket, to->type);
			toset_cancel(set, to->socket, to->type);
		}
	}
}

expiry_t toset_nearest_expiry(struct toset *set)
{
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	expiry_t nearest = EXPIRY_MAX;
	for (size_t type = 0; type < TO_TYPE_MAX; type++) {
		struct to *to = nearest_to(set, type);
		if (to)
			nearest = MIN(nearest, ms_to_expire(to, &now));
	}
	return nearest;
}
