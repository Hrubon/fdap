#ifndef TIMEOUT_H
#define TIMEOUT_H

#include "common.h"
#include "list.h"
#include "objpool.h"
#include <inttypes.h>

/*
 * Represents expiration time in milliseconds.
 */
typedef uint32_t expiry_t;

/*
 * Expiration value which is interpreted as no expiration.
 */
#define EXPIRY_NONE	0

/*
 * Maximum expiration value.
 */
#define EXPIRY_MAX	UINT32_MAX

/*
 * Type of a time-out.
 */
enum to_type
{
	TO_IDLE,
	TO_RX,
	TO_TX,
	TO_DOWN,
	TO_TYPE_MAX,
};

/*
 * Get a human-readable name for time-out type `type`.
 */
const char *strto(enum to_type type);

/*
 * A time-out. The `exp_s` and `exp_ms` fields are the seconds and milliseconds
 * part of the expiration time, respectively. This is not the wall-clock time,
 * but rather the time determined by `clock_gettime` at the time of expiration
 * (using `CLOCK_MONOTONIC`).
 */
struct to
{
	struct lnode n;		/* node in the time-out list */
	struct socket *socket;	/* socket which configured the time-out */
	uint32_t exp_s;		/* expiration seconds */
	uint16_t exp_ms;	/* expiration milliseconds */
	byte_t type;		/* type of the time-out, see `enum to_type` */
};

/*
 * Set of time-outs. This data structure can manipulate large collections of
 * time-outs configured by many different sockets efficiently, provided that
 * the set of different time-out types is small (and, like here, known at
 * compile-time). All operations it provides are $O(1)$ unless otherwise noted.
 */
struct toset
{
	struct objpool to_pool; 	/* pool for `to` structures */
	struct list tos[TO_TYPE_MAX];	/* lists of time-outs grouped by type */
	expiry_t expiry[TO_TYPE_MAX];	/* expiration per time-out type */
};

/*
 * Initialize new time-out set `set`.
 */
void toset_init(struct toset *set);

/*
 * Free the time-out set `set`.
 */
void toset_free(struct toset *set);

/*
 * Configure the time-out `type` to `ms` milliseconds. This operation should
 * be called before any time-out of type `type` is set, otherwise time-outs
 * may expire later than desired.
 */
void toset_set_expiry(struct toset *set, enum to_type type, expiry_t ms);

/*
 * Configure the time-out type `type` on `socket` in `set`. If the time-out is
 * already configured, the behaviour is the same as if the time-out was canceled
 * first with `toset_cancel` and then configured again.
 */
void toset_reset(struct toset *set, struct socket *socket, enum to_type type);

/*
 * Cancel the time-out type `type` configured for `socket` in `set`. It's safe
 * to call this operation even if no such time-out is set.
 */
void toset_cancel(struct toset *set, struct socket *socket, enum to_type type);

/*
 * Cancel all time-outs that `socket` has configured in `set`.
 */
void toset_cancel_all(struct toset *set, struct socket *socket);

/*
 * Find all expired time-outs, notify the sockets which configured them and
 * cancel them.
 */
void toset_check_expired(struct toset *set);

/*
 * Return the number of milliseconds till the nearest configured time-out in
 * `set` expires.
 */
expiry_t toset_nearest_expiry(struct toset *set);

#endif
