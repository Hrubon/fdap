#include "array.h"
#include "cbor.h"
#include "debug.h"
#include "iter.h"
#include "list.h"

#define RECS_INIT_SIZE	8 

struct record *iter_next(struct iter *iter)
{
	return iter->ops->next(iter);
}

void iter_destroy(struct iter *iter)
{
	iter->ops->destroy(iter);
}

/******************************** iter_null ********************************/

static struct record *iter_null_next(struct iter *iter)
{
	(void) iter;
	return NULL;
}

static void iter_null_destroy(struct iter *iter)
{
	(void) iter;
}

struct iter_ops iter_null_ops = {
	.next = iter_null_next,
	.destroy = iter_null_destroy,
};

struct iter iter_null = {
	.ops = &iter_null_ops,
};

struct iter *iter_new_null(void)
{
	return &iter_null;
}

/******************************** iter_single ********************************/

struct iter_single
{
	struct iter base;
	struct record *rec;
};

static struct record *iter_single_next(struct iter *base)
{
	struct iter_single *iter = container_of(base, struct iter_single, base);
	struct record *next = iter->rec;
	iter->rec = NULL;
	return next;
}

static void iter_single_destroy(struct iter *base)
{
	free(container_of(base, struct iter_single, base));
}

struct iter_ops iter_single_ops = {
	.next = iter_single_next,
	.destroy = iter_single_destroy,
};

struct iter *iter_new_single(struct record *rec)
{
	struct iter_single *iter = fdap_malloc(sizeof(*iter));
	iter->base.ops = &iter_single_ops;
	iter->rec = rec;
	return &iter->base;
}

/******************************** iter_list ********************************/

struct iter_list
{
	struct iter base;
	struct lnode *cur;
	version_t version;
};

struct record *list_iter_next(struct iter *base)
{
	struct iter_list *iter = container_of(base, struct iter_list, base);
	struct record *r;
	struct record *older = NULL;
	for (;;) {
		iter->cur = iter->cur->next;
		if (!iter->cur)
			break;
		r = container_of(iter->cur, struct record, n);
		/* we always commit all records */
		assert(!(r->flags & RECF_NEW));
		assert(!(r->flags & RECF_DIRTY));
		/* ignore changes made in the future */
		if (r->version > iter->version) {
			/* return older version if any */
			if (older && r->id == older->id)
				return older;
			continue;
		}
		/* check whether the record was deleted */
		if (r->flags & RECF_DEL)
			continue;
		/* if there's a newer version, keep searching (but remember this one) */
		if (r->flags & RECF_OLD) {
			older = r;
			continue;
		}
		return r;
	}
	return NULL;
}

void list_iter_destroy(struct iter *base)
{
	free(container_of(base, struct iter_list, base));
}

struct iter_ops list_iter_ops = {
	.next = list_iter_next,
	.destroy = list_iter_destroy,
};

struct iter *iter_new_list(struct list *l, version_t version)
{
	struct iter_list *iter = fdap_malloc(sizeof(*iter));
	iter->base.ops = &list_iter_ops;
	iter->cur = &l->head;
	iter->version = version;
	return &iter->base;
}

/******************************** iter_filter ********************************/

struct iter_filter
{
	struct iter base;
	struct iter *inner;
	struct filter *f;
	struct keystore *keys;
};

static struct record *iter_filter_next(struct iter *base)
{
	struct iter_filter *iter = container_of(base, struct iter_filter, base);
	struct record *r;
	while ((r = iter_next(iter->inner)) != NULL)
		if (filter_match(iter->f, r, iter->keys))
			break;
	return r;
}

static void iter_filter_destroy(struct iter *base)
{
	struct iter_filter *iter = container_of(base, struct iter_filter, base);
	iter_destroy(iter->inner);
	free(iter);
}

struct iter_ops iter_filter_ops = {
	.next = iter_filter_next,
	.destroy = iter_filter_destroy,
};

struct iter *iter_new_filter(struct iter *inner, struct filter *f, struct keystore *keys)
{
	struct iter_filter *iter = fdap_malloc(sizeof(*iter));
	iter->base.ops = &iter_filter_ops;
	iter->inner = inner;
	iter->f = f;
	iter->keys = keys;
	return &iter->base;
}

/******************************** iter_cbor ********************************/

struct iter_cbor
{
	struct iter base;
	struct cbor *c;
	struct record *recs;
	bool last;
};

static struct record *decode_record(struct iter_cbor *iter)
{
	record_id_t id = cbor_read_u32(iter->c);
	if (id == 0)
		return NULL;
	struct record *rec = ARRAY_RESERVE(iter->recs);
	record_init(rec);
	rec->id = id;
	rec->version = cbor_read_u32(iter->c);
	cbor_read_item(iter->c, rec->attrs);
	if (rec->attrs->type == CBOR_TYPE_MAP)
		rec->nattrs = rec->attrs->u32;
	return rec;
}

static struct record *iter_cbor_next(struct iter *base)
{
	struct iter_cbor *iter = container_of(base, struct iter_cbor, base);
	if (iter->last)
		return NULL;
	struct record *rec = decode_record(iter);
	if (!rec)
		iter->last = true;
	return rec;
}

static void iter_cbor_destroy(struct iter *base)
{
	struct iter_cbor *iter = container_of(base, struct iter_cbor, base);
	for (size_t i = 0; i < ARRAY_SIZE(iter->recs); i++) {
		cbor_item_free(iter->recs[i].attrs);
	}
	array_destroy(iter->recs);
	free(iter);
}

struct iter_ops iter_cbor_ops = {
	.next = iter_cbor_next,
	.destroy = iter_cbor_destroy,
};

struct iter *iter_new_cbor(struct cbor *c)
{
	struct iter_cbor *iter = fdap_malloc(sizeof(*iter));
	iter->base.ops = &iter_cbor_ops;
	iter->c = c;
	iter->recs = array_new(RECS_INIT_SIZE, sizeof(*iter->recs));
	iter->last = false;
	return &iter->base;
}
