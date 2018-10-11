#ifndef ITER_H
#define ITER_H

#include "filter.h"
#include "memory.h"

/*
 * Various record iterators. These objects are used to walk subsets of storage
 * records.
 */

/*
 * Represents an iterator. Iterators provide an interface to walk through the
 * results of index search operations.
 */
struct iter
{
	struct iter_ops *ops;	/* iterator operations */
};

/*
 * Return next record in the set of results over which iterator `iter` iterates.
 */
struct record *iter_next(struct iter *iter);

/*
 * Operations of an iterator.
 */
struct iter_ops
{
	struct record *(*next)(struct iter *iter);
	void (*destroy)(struct iter *iter);
};

/*
 * Create a null iterator. Calling `iter_next` on this iterator will always
 * return `NULL`, calling `iter_destroy` won't do a thing. (But do call it.)
 */
struct iter *iter_new_null(void);

/*
 * Create an iterator which will only return a single record when `iter_next`
 * is called for the first time.
 */
struct iter *iter_new_single(struct record *rec);

/*
 * Create an iterator which iterates over all records in list `l`
 * consecutively.
 */
struct iter *iter_new_list(struct list *l, version_t version);

/*
 * Create an iterator which iterates over `inner` and filters the results using
 * `f`. The iterator returned takes ownership of the `inner` iterator. The
 * `keys` keystore is used to translate first level of attribute names to
 * attribute IDs.
 */
struct iter *iter_new_filter(struct iter *inner, struct filter *f, struct keystore *keys);


/*
 * Create an iterator which iterates over the CBOR-encoded FDAP response and
 * decodes data from the unerlying CBOR stream `c` on demand. The records in
 * the CBOR response should contain string keys.
 */
struct iter *iter_new_cbor(struct cbor *c);

/*
 * Destroy the iterator `iter`. If the iterator takes other iterators as
 * arguments, they will be destroyed as well.
 */
void iter_destroy(struct iter *iter);

#endif
