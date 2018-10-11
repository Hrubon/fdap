#ifndef STORAGE_H
#define STORAGE_H

/*
 * Storage is a device which provides a set of operations for storing and
 * loading of records and record searching.
 */

#include "keystore.h"
#include "record.h"
#include "iter.h"
#include <inttypes.h>

/*
 * Result of a storage operation.
 */
enum storage_result
{
	STOR_OK,	/* all good */
	STOR_NXREC,	/* record does not exist */
	STOR_REFS,	/* some references prevent the operation */
	STOR_COMMIT,	/* failed to commit transaction */
};

/*
 * Type of a storage result operation.
 */
typedef enum storage_result	storage_result_t;

/*
 * Name of the primary identifier of a record.
 */
extern char *id_attr;

/*
 * Name of the field containing record type information.
 */
extern char *types_attr;

/*
 * Operations of a persistent storage.
 */
struct storage_ops
{
	storage_result_t (*update)(struct storage *stor, struct record *record);
	struct record *(*get)(struct storage *stor, record_id_t id);
	storage_result_t (*remove)(struct storage *stor, record_id_t id);
	struct iter *(*walk)(struct storage *stor);
	struct iter *(*search)(struct storage *stor, struct filter *f);
	void (*destroy)(struct storage *stor);
};

/*
 * A persistent storage.
 */
struct storage
{
	struct storage_ops *ops;	/* storage operations */
	struct keystore attrs_store;	/* attributes keystore */
	record_id_t last_id;		/* last used ID */
	version_t version;		/* maximum version used */
};

/*
 * Initialize the storage `stor`, configure `ops` as storage operations.
 *
 * Do not call this function directly, it is used by the various storage
 * implementations only.
 */
void storage_init(struct storage *stor, struct storage_ops *ops);

/*
 * Retrieve a record with ID `id` from storage `stor`, or NULL if record with
 * this ID does not exist.
 */
struct record *storage_get(struct storage *stor, record_id_t id);

/*
 * Update the record `rec` in storage `stor`.
 *
 * If the storage does not contain record with an ID same as the updated
 * record's, the record will be inserted into the storage with a new ID.
 * (This is always the case when record's ID is set to `RECORD_ID_NONE`.)
 * Otherwise, a record with matching ID is sought and its attributes will be
 * updated according to the values of `rec`.
 */
storage_result_t storage_update(struct storage *stor, struct record *rec);

/*
 * Return an iterator which iterates over all records in the storage.
 */
struct iter *storage_walk(struct storage *stor);

/*
 * Delete record with ID `id` from storage `stor`.
 */
storage_result_t storage_remove(struct storage *stor, record_id_t id);

/*
 * Search storage `stor` for records matching filter `f`.
 */
struct iter *storage_search(struct storage *stor, struct filter *f);

/*
 * Destroy the storage object `stor`.
 */
void storage_destroy(struct storage *stor);

struct storage *storage_local_new(void);
struct storage *storage_dummy_new(char *path);

#endif
