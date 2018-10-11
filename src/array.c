#include "array.h"
#include "memory.h"
#include "log.h"
#include <assert.h>
#include <stdlib.h>

/*
 * Resize `a` so that it has capacity for `new_capacity` items at `item_size`
 * bytes per item. If `a` is `NULL`, allocate a new array.
 */
static void *resize(void *a, size_t new_capacity, size_t item_size)
{
	LOGF(LOG_DEBUG, "Resizing array (a=%p, new_capacity=%lu)", a, new_capacity);
	size_t alloc_size = sizeof(struct array_hdr) + new_capacity * item_size;
	struct array_hdr *hdr = a ? ARRAY_HDR(a) : NULL;
	hdr = fdap_realloc(hdr, alloc_size);
	hdr->item_size = item_size;
	hdr->capacity = new_capacity; 
	return hdr + 1;

}

void *array_new(size_t init_capacity, size_t item_size)
{
	assert(init_capacity > 0);
	void *a = resize(NULL, init_capacity, item_size);
	ARRAY_SIZE(a) = 0;
	return a;
}

void array_destroy(void *a)
{
	LOGF(LOG_DEBUG, "Freeing array (a=%p)", a);
	free(ARRAY_HDR(a));
}

void *array_claim(void *a, size_t num_items)
{
	struct array_hdr *hdr = ARRAY_HDR(a);
	if (hdr->num_items + num_items > hdr->capacity) {
		a = resize(a, 2 * hdr->capacity, hdr->item_size);
		hdr = ARRAY_HDR(a);
	}

	hdr->num_items += num_items;

	return a;
}

void *array_ensure_index(void *a, size_t index)
{
	if (index < ARRAY_HDR(a)->capacity)
		return a;
	size_t new_capacity = MAX(2 * ARRAY_HDR(a)->capacity, index + 1);
	return resize(a, new_capacity, ARRAY_HDR(a)->item_size);
}
