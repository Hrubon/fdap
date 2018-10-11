#include "array.h"
#include "debug.h"
#include "record.h"
#include <assert.h>
#include <time.h>

#define TEST_SIZE	1024

int main(void)
{
	unsigned long seed = time(NULL);
	srandom(seed);
	DEBUG_PRINTF("Using seed %lu", seed);

	struct record *rec = record_new(NULL, TEST_SIZE);
	key_id_t *ids = array_new(TEST_SIZE, sizeof(*ids));
	key_id_t *removed_ids = array_new(TEST_SIZE / 2, sizeof(*removed_ids));

	/* insert `TEST_SIZE` attributes into the record, store IDs to `ids' */
	key_id_t id = random() % KEY_ID_MAX;
	for (size_t i = 0; i < TEST_SIZE; i++) {
		assert(record_insert(rec, id) != NULL);
		ARRAY_PUSH(ids, id);
		id += 1 + (random() % 10); /* non-trivial monotonic sequence */
	}

	/* remove roughly half of the record's attributes at random */
	while (ARRAY_SIZE(ids) > TEST_SIZE / 2) {
		size_t idx = random() % ARRAY_SIZE(ids);
		key_id_t id = ids[idx];
		assert(record_has(rec, id));
		assert(record_getby_id(rec, id)->u16 == id);
		assert(record_remove(rec, id));
		DEBUG_PRINTF("Deleted item, ID=%d", id);
		ARRAY_DROP(ids, idx);
		assert(!record_has(rec, id));
		ARRAY_PUSH(removed_ids, id);
	}

	/* check that all removed attributes are really gone */
	for (size_t i = 0; i < ARRAY_SIZE(removed_ids); i++)
		assert(!record_has(rec, removed_ids[i]));

	/* check that the record has all non-deleted attributes */
	for (size_t i = 0; i < ARRAY_SIZE(ids); i++) {
		assert(record_has(rec, ids[i]));
		assert(record_getby_id(rec, ids[i])->u16 == ids[i]);
	}

	/* try removing already removed attributes */
	for (size_t i = 0; i < ARRAY_SIZE(removed_ids); i++)
		assert(!record_remove(rec, removed_ids[i]));

	/* remove all attributes at random */
	while (!ARRAY_EMPTY(ids)) {
		size_t idx = random() % ARRAY_SIZE(ids);
		key_id_t id = ids[idx];
		assert(record_has(rec, id));
		record_remove(rec, id);
		ARRAY_DROP(ids, idx);
	}

	record_destroy(NULL, rec);
	array_destroy(ids);
	array_destroy(removed_ids);
}
