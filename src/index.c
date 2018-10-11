#include "index.h"
#include <assert.h>

/* TODO provide slow general default implementation instead */
static struct iter *find_range_not_supported(struct index *idx, struct cbor_item *a, struct cbor_item *b)
{
	(void) idx;
	(void) a;
	(void) b;
	assert(0);
}

/* TODO provide slow general default implementation instead */
static struct iter *find_in_not_supported(struct index *idx, struct list *vals)
{
	(void) idx;
	(void) vals;
	assert(0);
}

void index_ops_init(struct index_ops *ops)
{
	ops->contains = NULL;
	ops->find = NULL;
	ops->reset = NULL;
	ops->destroy = NULL;

	/* these operations are not mandatory */
	ops->find_range = find_range_not_supported;
	ops->find_in = find_in_not_supported;
}

bool index_contains(struct index *idx, struct cbor_item *val)
{
	return idx->ops->contains(idx, val);
}

struct iter *index_find(struct index *idx, struct cbor_item *val)
{
	return idx->ops->find(idx, val);
}

struct iter *index_find_range(struct index *idx, struct cbor_item *a, struct cbor_item *b)
{
	return idx->ops->find_range(idx, a, b);
}

struct iter *index_find_in(struct index *idx, struct list *vals)
{
	return idx->ops->find_in(idx, vals);
}

void index_reset(struct index *idx)
{
	idx->ops->reset(idx);
}

void index_destroy(struct index *idx)
{
	idx->ops->destroy(idx);
}
