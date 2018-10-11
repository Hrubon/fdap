#include "array.h"
#include "log.h"
#include "keystore.h"
#include <string.h>

#define	ENTRY_POOL_BLOCK_SIZE	16

static struct keystore_entry *new_entry(struct keystore *store, char *key)
{
	struct keystore_entry *entry = objpool_alloc(&store->entry_pool);
	entry->key = strdup(key);
	entry->refcnt = 0; /* TODO start using this */
	/*
	 * Allocate an ID for the key: either reused a freed ID or generate
	 * next ID in the sequence of IDs. Reusing old IDs makes arrays which
	 * are indexed by them compact (with only a few gaps).
	 */
	if (!ARRAY_EMPTY(store->free_ids))
		entry->id = ARRAY_POP(store->free_ids);
	else
		entry->id = store->id_seq++;
	list_insert(&store->key_to_id, &entry->n);
	ARRAY_SET(store->id_to_entry, (size_t)entry->id, entry);
	LOGF(LOG_DEBUG, "New key-store entry (key=%s, ID=%u)", entry->key, entry->id);
	return entry;
}

static void delete_entry(struct keystore *store, struct keystore_entry *entry)
{
	LOGF(LOG_DEBUG, "Deleting entry (key=%s, ID=%u)", entry->key, entry->id);
	ARRAY_PUSH(store->free_ids, entry->id);
	free(entry->key);
	objpool_dealloc(&store->entry_pool, entry);
}

void keystore_init(struct keystore *store)
{
	objpool_init(&store->entry_pool, sizeof(struct keystore_entry), ENTRY_POOL_BLOCK_SIZE);
	list_init(&store->key_to_id);
	store->id_seq = 0;
	store->id_to_entry = array_new(ENTRY_POOL_BLOCK_SIZE, sizeof(*store->id_to_entry));
	store->free_ids = array_new(ENTRY_POOL_BLOCK_SIZE, sizeof(*store->free_ids));
}

void keystore_free(struct keystore *store)
{
	list_walk(store->key_to_id, n) {
		struct keystore_entry *entry = container_of(n, struct keystore_entry, n);
		delete_entry(store, entry);
	}
	objpool_free(&store->entry_pool);
	array_destroy(store->id_to_entry);
	array_destroy(store->free_ids);
}

static struct keystore_entry *find(struct keystore *store, char *key)
{
	list_walk(store->key_to_id, n) {
		struct keystore_entry *entry = container_of(n, struct keystore_entry, n);
		if (strcmp(entry->key, key) == 0)
			return entry;
	}
	return NULL;
}

key_id_t keystore_key_to_id(struct keystore *store, char *key)
{
	struct keystore_entry *entry = find(store, key);
	if (!entry)
		entry = new_entry(store, key);
	return entry->id;
}

char *keystore_id_to_key(struct keystore *store, key_id_t id)
{
	return store->id_to_entry[id]->key;
}
