#ifndef CACHE_H
#define CACHE_H

#include "cbor.h"
#include "storage.h"

/*
 * An in-memory record cache. Provides fast read access to records. Supports
 * search operations.
 */
struct cache
{
	struct index **indices;	/* indices indexed by attr ID */
};

void cache_init(struct cache *cache);
void cache_free(struct cache *cache);
void cache_flush(struct cache *cache);

void cache_add_index(struct cache *cache, const char *key, struct index *index);
void cache_remove_index(struct cache *cache, const char *key);

void cache_search(struct cache *cache, const char *key, struct cbor_item value);

int cache_update(struct cache *cache, struct record *record);
void cache_remove(struct cache *cache, record_id_t id);

#endif
