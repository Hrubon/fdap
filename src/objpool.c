#include "objpool.h"
#include "log.h"
#include "memory.h"
#include <assert.h>

/*
 * Internally, this simple memory pool does the following: instead of
 * allocating individual memory chunk on each call to `objpool_alloc',
 * it allocates blocks which can hold a preconfigured number of fixed-size
 * objects. It is thus a fixed-size allocator.
 *
 * The pool cannot be used for variable-sized allocations. It is thus
 * suitable for allocation of many small objects of the same type, in
 * which case it provides a significant space/time savings over individually
 * `malloc'd objects.
 *
 * For example, the pool can be configured to allocate 32 B-sized objects,
 * allocating 32 of them at once.
 *
 * When an allocation request arrives, the pool either returns the next free
 * object from some block, or allocates a whole new block if no block
 * has a free object which could be returned.
 *
 * The free objects form a linked list. A ``fresh'' block only contains
 * free objects:
 *
 *     +---+---+---+---+---+---+---+---+---+---+---+---+---+--   --+---+
 *     | F | F | F | F | F | F | F | F | F | F | F | F | F |  ...  | F |
 *     +---+---+---+---+---+---+---+---+---+---+---+---+---+--   --+---+
 *
 * In such a block, the linked list of free objects starts with the first
 * object of the block, and then goes through every other object in the
 * block sequentially. The initial list of free objects is constructed
 * by `init_block'.
 *
 * As allocations come in, the pool allocates memory from the block.
 * Allocating from the pool means removing an object form the list
 * of free objects and returning a pointer to the object.
 *
 *     +---+---+---+---+---+---+---+---+---+---+---+---+---+--   --+---+
 *     | X | X | X | X | X | X | X | X | X | F | F | F | F |  ...  | F |
 *     +---+---+---+---+---+---+---+---+---+---+---+---+---+--   --+---+
 *
 * Objects can be de-allocated, returning them to the list of free
 * objects by a call to `objpool_dealloc'. After that, used/unused
 * objects may no longer form contiguous areas within a block. But no
 * space or time is wasted by fragmentation, because the allocated
 * objects are fixed-size. The situation after allocating/deallocating
 * may look like this:
 *
 *     +---+---+---+---+---+---+---+---+---+---+---+---+---+--   --+---+
 *     | X | F | X | F | X | X | X | F | X | F | X | X | F |  ...  | X |
 *     +---+---+---+---+---+---+---+---+---+---+---+---+---+--   --+---+
 *
 * With more blocks allocated, the situation is similar. But as the list
 * of free blocks is global (per-pool, not per-block), it usually contains
 * objects from multiple blocks, depending on the sequence of allocations
 * and deallocations.
 *
 * The blocks themselves form a linked list, too, so they can be freed
 * upon a call to `objpool_free'. (Remember: the blocks are individually
 * allocated chunks of memory, the objects are not.)
 *
 *     +---+---+--   --+---+    +---+---+--   --+---+
 *     | X | X |  ...  | X |--->| X | F |  ...  | X |---> ... ---> NULL
 *     +---+---+--   --+---+    +---+---+--   --+---+
 *
 * To simplify the memory fiddling, `objpool_block' and `objpool_unused'
 * structures are defined in the header file. An `objpool_block' is at the
 * beginning of the memory allocated for each block; likewise,
 * `objpool_unused' is at the beginning of each unused object in a block.
 * These structures only hold one pointer each to construct the linked
 * list of blocks/free objects with relative ease and a bit more type
 * checking.
 *
 * As a result, the allocated object size needs to be at least
 * sizeof(struct objpool_unused).
 */

/*
 * Initialize the linked-list structure of free objects within @block.
 */
static void init_block(struct objpool *pool, struct objpool_block *block)
{
	void *mem = block + 1; /* points right after block header */
	struct objpool_unused *unused;
	size_t i;

	for (i = 0; i < pool->objs_per_block; i++) {
		unused = mem;
		unused->next = pool->first_unused;
		pool->first_unused = unused;

		mem = (unsigned char *)mem + pool->obj_size;
	}
}

/*
 * Allocate a new block (a bunch of fixed-sized objects) in @pool
 * to satisfy allocation requests.
 */
static void alloc_new_block(struct objpool *pool)
{
	struct objpool_block *new_block;

	new_block = fdap_malloc(pool->block_size);

	LOGF(LOG_DEBUG, "Allocated new block (alloc_size=%zu B)", pool->block_size);

	new_block->next = pool->first_block;
	pool->first_block = new_block;
	init_block(pool, new_block);
	pool->num_blocks++;
}

/******************************** public API ********************************/

void objpool_init(struct objpool *objpool, size_t obj_size, size_t objs_per_block)
{
	size_t min_size;

	assert(obj_size >= sizeof(struct objpool_unused));
	assert(objs_per_block > 1);

	objpool->obj_size = obj_size;
	objpool->objs_per_block = objs_per_block;
	objpool->first_block = NULL;
	objpool->first_unused = NULL;
	objpool->num_objs = 0;
	objpool->num_blocks = 0;

	min_size = obj_size * objs_per_block + sizeof(struct objpool_block);
	objpool->block_size = min_size;

	while (min_size > objpool->block_size)
		objpool->block_size *= 2;
}

void *objpool_alloc(struct objpool *pool)
{
	void *mem;

	if (pool->first_unused == NULL)
		alloc_new_block(pool);

	assert(pool->first_unused != NULL);

	mem = pool->first_unused;
	pool->first_unused = pool->first_unused->next;

	pool->num_objs++;

	return mem;
}

void objpool_dealloc(struct objpool *pool, void *mem)
{
	struct objpool_unused *unused = mem;

	unused->next = pool->first_unused;
	pool->first_unused = unused;

	assert(pool->num_objs > 0);
	pool->num_objs--;
}

void objpool_reset(struct objpool *pool)
{
	struct objpool_block *block;

	pool->first_unused = NULL;
	pool->num_objs = 0;

	for (block = pool->first_block; block != NULL; block = block->next)
		init_block(pool, block);
}

void objpool_free(struct objpool *pool)
{
	LOGF(LOG_DEBUG, "Freeing pool (pool=%p)", (void *)pool);
	struct objpool_block *block = pool->first_block;
	while (pool->first_block) {
		block = pool->first_block;
		pool->first_block = pool->first_block->next;
		free(block);
	}
}
