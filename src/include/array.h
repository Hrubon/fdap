#ifndef ARRAY_H
#define ARRAY_H

#include <stdlib.h>
#include "common.h"

/*
 * A growing array of arbitrary items implemented using mostly macros. This
 * allows for a nice and type-safe interface while being quite comfortable to
 * work with.
 */

#include <stddef.h>

/*
 * Header of a growing array. Each time `array_new` is called, the `array_hdr`
 * struct is allocated just before the actual pointer returned. This structure
 * holds information needed for automatic resizing of the array.
 */
struct array_hdr
{
	size_t num_items;	/* number of items actually contained in the array */
	size_t capacity;	/* current capacity of the array */
	size_t item_size;	/* size of a single item */
};

#define ARRAY_HDR(a)		((struct array_hdr *)((unsigned char *)(a) - sizeof(struct array_hdr)))

/*
 * Return the size of the array (the number of items it contains, not the capacity).
 */
#define ARRAY_SIZE(a)		(ARRAY_HDR(a)->num_items)

#define ARRAY_LAST_INDEX(a)	(ARRAY_SIZE(a) - 1)

/*
 * The last item of the array. This is an lvalue and can be assigned.
 */
#define ARRAY_LAST(a)		((a)[ARRAY_LAST_INDEX(a)])

#define ARRAY_ENSURE(a, idx)	((a) = array_ensure_index(a, idx))

/*
 * Insert an item at the end of the array, return a pointer to it. This is
 * basically an allocation of memory from the array.
 */
#define ARRAY_RESERVE(a)	(ARRAY_ENSURE(a, ARRAY_SIZE(a)), ARRAY_SIZE(a)++, &ARRAY_LAST(a))

/*
 * Set `a[idx] = val`. If `idx` is outside of the bounds of the array, grow
 * the array as needed.
 */
#define ARRAY_SET(a, idx, val)	(ARRAY_ENSURE(a, idx), (a)[idx] = val, ARRAY_SIZE(a) = MAX(ARRAY_SIZE(a), idx + 1))

/*
 * Append `val` at the end of `a`.
 */
#define ARRAY_PUSH(a, val)	(ARRAY_SET(a, ARRAY_SIZE(a), val))

/*
 * Remove last item of `a` and return it.
 */
#define ARRAY_POP(a)		((a)[--ARRAY_SIZE(a)])

/*
 * Is the array empty?
 */
#define ARRAY_EMPTY(a)		(ARRAY_SIZE(a) == 0)

/*
 * Replace-drop item at index `idx` in the array, i.e. override `a[idx]` with
 * the last item of the array and shrink the array by one. This operation
 * changes order of items! Constant time.
 */
#define ARRAY_DROP(a, idx)	(a[idx] = ARRAY_LAST(a), ARRAY_SIZE(a)--)

/*
 * Replace-drop a random item. See `ARRAY_DROP`. This operation changes order
 * of items! Constant time.
 */
#define ARRAY_DROP_RANDOM(a)	(ARRAY_DROP(a, random() % ARRAY_SIZE(a)))

/*
 * Allocate an array of `item_size`-sized items.
 */
void *array_new(size_t num_items, size_t item_size);

/*
 * Destroy array `a` which was previously allocated using `array_new`.
 * The array will be allocated to have space for `num_items` initially.
 */
void array_destroy(void *a);

void *array_ensure_index(void *a, size_t index);

#endif
