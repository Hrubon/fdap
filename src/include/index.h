#ifndef INDEX_H
#define INDEX_H

#include "list.h"
#include "iter.h"
#include "cbor.h"
#include <stdbool.h>

/*
 * Index is any data structure which makes searching faster.
 */
struct index
{
	struct index_ops *ops;	/* index operations */
};

/*
 * Operations of an index.
 */
struct index_ops
{
	bool (*contains)(struct index *idx, struct cbor_item *val);
	struct iter *(*find)(struct index *idx, struct cbor_item *val);
	struct iter *(*find_range)(struct index *idx, struct cbor_item *a, struct cbor_item *b);
	struct iter *(*find_in)(struct index *idx, struct list *vals);
	void (*reset)(struct index *idx);
	void (*destroy)(struct index *idx);
};

void index_ops_init(struct index_ops *ops);

bool index_contains(struct index *idx, struct cbor_item *val);
struct iter *index_find(struct index *idx, struct cbor_item *val);
struct iter *index_find_range(struct index *idx, struct cbor_item *a, struct cbor_item *b);
struct iter *index_find_in(struct index *idx, struct list *vals);
void index_reset(struct index *idx);
void index_destroy(struct index *idx);

#endif
