/*
 * Simple fixed-size memory allocator.
 */

#ifndef OBJPOOL_H
#define OBJPOOL_H

#include <stdlib.h>

/*
 * Object pool execution context.
 */
struct objpool
{
	struct objpool_block *first_block;	/* first block in a list of all blocks */
	struct objpool_unused *first_unused;	/* first unused object in a list of unused */
	size_t obj_size;			/* size of a single allocation */
	size_t objs_per_block;			/* number of objects per block */
	size_t block_size;			/* (real) calculated size of a block */
	size_t num_objs;			/* number of allocated objects */
	size_t num_blocks;			/* number of allocated blocks */
};

/*
 * Represents a memory block in the pool.
 */
struct objpool_block
{
	struct objpool_block *next;	/* next block */
};

/*
 * Represents an unused object within a memory block.
 */
struct objpool_unused
{
	struct objpool_unused *next;	/* next unused object */
};

/*
 * Initialize `objpool` to handle `obj_size`-sized objects, allocating space for \\
 * `objs_per_block` of them at once.
 */
void objpool_init(struct objpool *pool, size_t obj_size, size_t objs_per_block);

/*
 * Reset the objpool to its initial state.
 *
 * NOTE: No memory will be freed.
 */
void objpool_reset(struct objpool *pool);

/*
 * Allocate a single object from the pool. The memory returned will be valid
 * until either `objpool_dealloc` or `objpool_free` is called.
 *
 * TODO: `objpool_alloc` should return aligned memory
 */
void *objpool_alloc(struct objpool *pool);

/*
 * De-allocate the memory `mem`, returning it to `pool` to satisfy further
 * allocation requests.
 */
void objpool_dealloc(struct objpool *pool, void *mem);

/*
 * Free all memory held by `pool`. This renders all memory handles previously
 * returned from the pool as invalid.
 */
void objpool_free(struct objpool *pool);

#endif
