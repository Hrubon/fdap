#include "array.h"
#include <assert.h>
#include <stdio.h>

#define INIT_CAPACITY	10
#define TEST_SIZE	1121

int main(void)
{
	size_t *arr = array_new(INIT_CAPACITY, sizeof(*arr));
	for (size_t i = 0; i < TEST_SIZE; i++)
		ARRAY_PUSH(arr, i);
	for (size_t i = TEST_SIZE; i >= 1; i--) {
		assert(ARRAY_SIZE(arr) == i);
		assert(ARRAY_POP(arr) == i - 1);
		assert(ARRAY_SIZE(arr) == i - 1);
	}
	array_destroy(arr);
	return 0;
}
