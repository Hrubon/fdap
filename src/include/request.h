#ifndef REQUEST_H
#define REQUEST_H

#include "cbor.h"
#include "filter.h"
#include "iter.h"
#include "record.h"

/*
 * FDAP operation.
 */
enum fdap_oper
{
	FDAP_AUTH = 1,
	FDAP_SEARCH,
	FDAP_GET,
	FDAP_CREATE,
	FDAP_UPDATE,
	FDAP_DELETE,
};


/*
 * FDAP `id` type.
 */
typedef record_id_t fdap_id_t;

/*
 * Get a human-readable name for the FDAP operation `oper`.
 */
const char *fdap_stroper(enum fdap_oper oper);

/*
 * FDAP authentication data.
 */
struct auth
{
	char *username;		/* user name -- a key for an entry to perform authentication on */
	char *pwd;		/* password hash or another authentication data */
};

/*
 * FDAP request.
 */
struct fdap_req
{
	enum fdap_oper oper;		/* FDAP operation */
	fdap_id_t id;			/* id of an entry */
	struct auth auth;		/* request authentication data */
	struct filter filter;		/* request filter */
	struct cbor_item entry;		/* CBOR directory entry (data payload) */
};

/*
 * Free all allocated resources within FDAP request `r`.
 */
void fdap_request_free(struct fdap_req *r);

/*
 * Result of an FDAP operation.
 */
enum fdap_res
{
	FDAP_OK				= 0,
	FDAP_NOT_FOUND			= 101,
	FDAP_ERR_INTERNAL		= 301,
	FDAP_ERR_NOT_IMPL		= 302,
	FDAP_ERR_STR_TOO_LONG		= 304,
	FDAP_ERR_INVALID_FILTER		= 401,
	FDAP_ERR_INVALID_ENTRY		= 402,
	FDAP_ERR_NOT_MAP		= 403,
	FDAP_ERR_INVALID_REF		= 404,
	FDAP_ERR_NOT_AUTH		= 501,
	FDAP_ERR_FORBIDDEN		= 502,
};

/*
 * Get a human-readable name for the FDAP result code `res`.
 */
const char *fdap_strerr(enum fdap_res res);

/*
 * Log FDAP specfic error, using the log module.
 */
void fdap_logerr(enum fdap_res res);

/*
 * FDAP response.
 */
struct fdap_resp
{
	struct iter *results;	/* results iterator */
	size_t num_changed;	/* number of changed records */
	enum fdap_res result;	/* result of the operation */
};

/*
 * Free all allocated resources within FDAP response`r` and
 * frees the memory.
 */
void fdap_response_destroy(struct fdap_resp *r);


#endif
