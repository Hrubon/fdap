#ifndef KEYSTORE_H
#define KEYSTORE_H

#include "list.h"
#include "objpool.h"
#include <inttypes.h>

/*
 * ID of a key in the keystore.
 */
typedef uint16_t	key_id_t;

/*
 * Maximum value of `key_id_t`.
 */
#define KEY_ID_MAX	UINT16_MAX

/*
 * Keystore is a simple data structure which is supposed to provide fast
 * translation from a dynamic set of strings to a (mostly) contiguous
 * range of small integers (called IDs, see `key_id_t`) and vice versa.
 *
 * This allows for fast string de-duplication (because the integers can
 * be used instead of the strings everywhere) and the IDs can be used
 * to directly index an array of data related to the string (for example
 * to find an index data structure given a column name).
 */
struct keystore
{
	struct list key_to_id;			/* TODO cuckoo */
	struct keystore_entry **id_to_entry;	/* ID to keystore entry array */
	key_id_t id_seq;			/* current value of ID sequence */
	key_id_t *free_ids;			/* free IDs (for which refcount fell below 0) */
	struct objpool entry_pool;		/* memory pool for entry objects */
};

/*
 * A single entry in the keystore.
 */
struct keystore_entry
{
	struct lnode n;		/* TODO cuckoo */
	key_id_t id;		/* ID of the key in the keystore */
	char *key;		/* the key */
	uint32_t refcnt;	/* reference counter */
};

/*
 * Initialize the keystore `store`.
 */
void keystore_init(struct keystore *store);

/*
 * Free the keystore `store`.
 */
void keystore_free(struct keystore *store);

/*
 * Use `store` to translate `key` to an ID. If `key` is not present in
 * `store`, it will be assigned a new unused ID.
 */
key_id_t keystore_key_to_id(struct keystore *store, char *key);

char *keystore_id_to_key(struct keystore *store, key_id_t id);

#endif
