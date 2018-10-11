#ifndef RECORD_H
#define RECORD_H

#include "aname.h"
#include "cbor.h"
#include "keystore.h"
#include "list.h"
#include <inttypes.h>
#include <stdbool.h>

/*
 * Type capable of holding record IDs.
 */
typedef uint32_t	record_id_t;

/*
 * A reserved ID value meaning nothing.
 */
#define RECORD_ID_NONE	0

/*
 * Type capable of holding record version.
 */
typedef uint32_t	version_t;

/*
 * Type capable of holding the number of attributes a record has (`nattrs`)
 * and the number of attributes a record can hold (`size`).
 */
typedef uint16_t	nattrs_t;

/*
 * Record flags.
 */
enum
{
	RECF_NEW = 1,	/* was never stored before */
	RECF_DIRTY = 2,	/* changes made since record was loaded or created */
	RECF_DEL = 4,	/* deleted record */
	RECF_OLD = 8,	/* a newer version exists */
};

/*
 * Note that in the API reference, the terms `entry`, `record`, and `document`
 * are used interchangeably.
 *
 * A valid FDAP document is a definite-length map with definite-length text
 * keys, whose values are arbitrary CBOR items. This structure represents FDAP
 * documents in a fairly compact way (16 bytes for the header and 16 bytes for
 * every key-value pair assuming `x64`), while being relatively simple and
 * efficient to work with.
 *
 * The key-value pairs which make up the document's root map are called
 * attributes. An attribute is an ID (an integer equivalent of the key) and the
 * value, which is a generic CBOR item. The ID of the attribute is stored in
 * the `u16` field of the corresponding CBOR item, simplifying memory layout.
 *
 * In memory, an array `attrs` of attributes follows every `record`. The array
 * has capacity for `size` attributes and holds `nattrs` of them. It is always
 * sorted by attribute ID, providing $\Theta(\log k)$ operations, where $k$ is
 * the number of attributes before the operation.
 *
 * This structure is designed to be used in a copy-on-write manner, i.e. when
 * changes are to be made to an existing record, changes are made to a copy of
 * the record instead (with clean-up and propagation of the changes happening
 * later). The number of attributes of the resulting record is either known in
 * advance or fairly simple to calculate; hence, most of the time, this
 * structure is expected to have `nattrs` $\approx$ `size`, wasting only very
 * little space on the `attrs` array.
 */
struct record
{
	struct lnode n;			/* TODO delete */
	version_t version;		/* this record's version */
	record_id_t id;			/* this record's ID */
	nattrs_t nattrs;		/* number of attributes */
	nattrs_t size;			/* size of the record */
	uint8_t flags;			/* various flags */
	uint8_t reserved[3];		/* reserved, must be zeroed */
	struct cbor_item attrs[1];	/* the attributes or the root map */
};

struct storage;

/*
 * Initializes the record.
 */
void record_init(struct record *rec);

/*
 * Allocate a new record in storage `stor` with size `size`.
 */
struct record *record_new(struct storage *stor, nattrs_t size);

/*
 * Allocate a new record in storage `stor` with size `size`. Initially, the
 * record will be the same as `orig` in all aspects. `size` must be at least
 * the size of the `orig` record. If `orig` is `NULL`, the operation behaves
 * exactly the same as `record_new`.
 *
 * This function is leveraged by the copy-on-write operations of the dummy
 * storage.
 */
struct record *record_dup(struct storage *stor, struct record *orig, nattrs_t new_size);

/*
 * Destroy the record `r` which was previously allocated in storage `stor`.
 */
void record_destroy(struct storage *stor, struct record *r);

/*
 * Does the record `r` have an attribute with ID `id`?
 */
bool record_has(struct record *r, key_id_t id);

/*
 * Get the attribute with ID `id` of record `r`.
 */
struct cbor_item *record_getby_id(struct record *r, key_id_t id);

/*
 * Get the attribute with name `dotname` of record `r`.
 */
struct cbor_item *record_getby_name(struct record *r, char *dotname);

struct cbor_item *record_getby_name_keys(struct record *r, char *dotname, struct keystore *keys);

/*
 * Get value of the attribute designated with the name `n` from `rec`.
 * The `kyes` keystore will be used to translate root-level keys to attribute IDs.
 *
 * FIXME Calling keystore_key_to_id is A BAD IDEA. This basically allows an
 *       attacker to deplete our key ID range quickly by simply sending loads
 *       of queries which touch non-existent attributes in the root key
 *       position. Fix this prior to releasing first stable version!
 */
struct cbor_item *record_getby_aname(struct record *r, struct aname *n, struct keystore *keys);

/*
 * Get the attribute with name `dotname` as integer `val` from record `r`.
 * If the attribute is integer, `true` is returned, `false` otherwise.
 */
bool record_get_int(struct record *r, char *dotname, int *val);

/*
 * Get the attribute with name `dotname` as string `val` from record `r`.
 * If the attribute is integer, `true` is returned, `false` otherwise.
 */
bool record_get_string(struct record *r, char *dotname, char **val);

/*
 * Get the attribute with name `dotname` as boolean `val` from record `r`.
 * If the attribute is integer, `true` is returned, `false` otherwise.
 */
bool record_get_bool(struct record *r, char *dotname, bool *val);

/*
 * Cast record `r` root map to the `cbor_item`.
 */
struct cbor_item *record_to_item(struct record *r);

/*
 * Insert attribute with ID `id` to the record `r`. This operation costs
 * $\Theta(\log k)$ where $k$ is the number of attributes in the record before the
 * insertion.
 *
 * If the record has no space for the new attribute (i.e. its `nattrs` equals
 * its `size`), `NULL` is returned. If the record already contains attribute
 * with ID `id`, it will be returned instead.
 */
struct cbor_item *record_insert(struct record *r, key_id_t id);

/*
 * Delete attriute with ID `id` from the record `r`. This operation costs
 * $\Theta(\log k)$ where $k$ is the number of attributes in the record before the
 * removal.
 *
 * This function will return `true` if `r` was found to have an attribute with
 * ID `id`. Otherwise, `false` will be returned and no attribute will be removed.
 */
bool record_remove(struct record *r, key_id_t id);

/*
 * Write a human-readable representation of `rec` into `buf`.
 */
void record_dump(struct record *rec, struct strbuf *buf);

/*
 * Encode record `rec` which lives in storage `stor` to CBOR stream `c`.
 */
void record_encode(struct record *rec, struct storage *stor, struct cbor *c, bool full);

/*
 * Decode next record from CBOR stream `c`. The record will be allocated from
 * `stor`.
 */
struct record *record_decode(struct storage *stor, struct cbor *c);

#endif
