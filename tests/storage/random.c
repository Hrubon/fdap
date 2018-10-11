#include "array.h"
#include "debug.h"
#include "memory.h"
#include "storage.h"
#include <time.h>

#define TEST_SIZE	1024

/*
 * Compare record identity matches: either both are `NULL`, or both are
 * non-`NULL` and IDs are the same.
 */
static bool cmp(struct record *a, struct record *b)
{
	if (a == NULL && b == NULL)
		return true;
	if (a && b && a->id == b->id)
		return true;
	DEBUG_EXPR("%p", (void *)a);
	DEBUG_EXPR("%p", (void *)b);
	return false;
}

int main(void)
{
	unsigned long seed = time(NULL);
	srandom(seed);
	DEBUG_PRINTF("Using seed %lu", seed);

	struct storage *stor = storage_dummy_new(NULL);
	struct record **records = array_new(TEST_SIZE, sizeof(*records));
	struct record **deleted = array_new(TEST_SIZE / 2, sizeof(*records));

	/* create a lot of random records */
	for (size_t i = 0; i < TEST_SIZE; i++) {
		struct record *new = record_new(stor, 1);
		new->id = RECORD_ID_NONE;
		ARRAY_PUSH(records, new);
		assert(storage_update(stor, new) == STOR_OK);
		new->id = 1 + i; /* TODO this is a bit of a hack */
	}

	/* try to find every record */
	for (size_t i = 0; i < ARRAY_SIZE(records); i++)
		assert(cmp(storage_get(stor, 1 + i), records[i]));

	/* drop half of the records at random */
	for (size_t i = 0; i < TEST_SIZE / 2; i++) {
		size_t rnd_idx = random() % ARRAY_SIZE(records);
		storage_remove(stor, records[rnd_idx]->id);
		ARRAY_PUSH(deleted, records[rnd_idx]);
		ARRAY_DROP(records, rnd_idx);
	}

	/* check that non-deleted items are still reachable */
	for (size_t i = 0; i < ARRAY_SIZE(records); i++)
		assert(cmp(storage_get(stor, records[i]->id), records[i]));
	
	/* check that no deleted items are found */
	for (size_t i = 0; i < ARRAY_SIZE(deleted); i++)
		assert(cmp(storage_get(stor, deleted[i]->id), NULL));

	/* delete all items in random order */
	while (!ARRAY_EMPTY(records)) {
		size_t rnd_idx = rand() % ARRAY_SIZE(records);
		storage_remove(stor, records[rnd_idx]->id);
		record_destroy(stor, records[rnd_idx]);
		ARRAY_DROP(records, rnd_idx);
	}

	/* destroy deleted records, too */
	for (size_t i = 0; i < ARRAY_SIZE(deleted); i++)
		record_destroy(stor, deleted[i]);

	storage_destroy(stor);
	array_destroy(records);
	array_destroy(deleted);
}
