#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include "array.h"
#include "debug.h"

#define TEST_SIZE	133

static bool array_contains(size_t *arr, size_t item)
{
	for (size_t i = 0; i < ARRAY_SIZE(arr); i++)
		if (arr[i] == item)
			return true;
	return false;
}

int main(void)
{
	srandom(time(NULL));
	/* create two arrays containing the same items */
	size_t *arr1 = array_new(TEST_SIZE, sizeof(*arr1));
	size_t *arr2 = array_new(TEST_SIZE, sizeof(*arr2));
	for (size_t i = 0; i < TEST_SIZE; i++) {
		ARRAY_PUSH(arr1, i);
		ARRAY_PUSH(arr2, i);
	}

	/* drop all items in random order */
	size_t *dropped = array_new(TEST_SIZE, sizeof(*dropped));
	while (!ARRAY_EMPTY(arr1)) {
		size_t idx = random() % ARRAY_SIZE(arr1);
		size_t item = arr1[idx];
		ARRAY_DROP(arr1, idx);
		ARRAY_PUSH(dropped, item);

		/* check `arr1` does not contain any dropped item */
		for (size_t i = 0; i < ARRAY_SIZE(dropped); i++)
			assert(!array_contains(arr1, dropped[i]));

		/* check that `arr1` is still subset of `arr2` */
		for (size_t i = 0; i < ARRAY_SIZE(arr1); i++)
			assert(array_contains(arr2, arr1[i]));
	}

	array_destroy(arr1);
	array_destroy(arr2);
	array_destroy(dropped);

	return EXIT_SUCCESS;
}
