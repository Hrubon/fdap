#include "array.h"
#include <assert.h>
#include <stdio.h>

#define INIT_CAPACITY	10
#define TEST_SIZE	1183

int main(void)
{
	size_t *arr = array_new(INIT_CAPACITY, sizeof(*arr));
	for (size_t i = 0; i < TEST_SIZE; i++) {
		assert(ARRAY_SIZE(arr) == i);
		ARRAY_PUSH(arr, i);
		assert(ARRAY_SIZE(arr) == i + 1);
		assert(arr[i] == i);
	}
	for (size_t i = 0; i < TEST_SIZE; i++)
		assert(arr[i] == i);
	array_destroy(arr);
	return 0;
}
