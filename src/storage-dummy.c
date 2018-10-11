#include "common.h"
#include "iobuf.h"
#include "debug.h"
#include "cbor.h"
#include <sys/stat.h>
#include <fcntl.h>
#include "list.h"
#include "storage.h"
#include <assert.h>
#include "log.h"
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

struct dummy
{
	struct storage base;	/* base storage object */
	struct list records;	/* list of records held in the storage */
	char *path;		/* path to the file which holds the storage */
};

static struct dummy *cast(struct storage *stor)
{
	return container_of(stor, struct dummy, base);
}

static struct record *get(struct storage *stor, record_id_t id)
{
	struct dummy *d = cast(stor);
	list_walk(d->records, n) {
		struct record *r = container_of(n, struct record, n);
		if (r->id != id || r->flags)
			continue;
		return r;
	}
	return NULL;
}

/*
 * Tag value which is understood as "reference to other record". Right now, we
 * use the IANA reference value whose semantics is slightly different.
 */
#define REF_TAG	29

/*
 * Returns true iff `item` is a reference to `id` or contains an item which
 * is a reference to `id` recursively.
 *
 * TODO Major vs type
 */
static bool has_ref(struct cbor_item *item, record_id_t id)
{
	struct cbor_item t = *item;
	cbor_tag_t tag;
	bool ref = false;
	while (cbor_item_strip_tag(&t, &tag)) {
		if (tag == REF_TAG) {
			ref = true;
			break;
		}
	}
	switch (t.type) {
	case CBOR_TYPE_UINT:
		return ref && t.u64 == id;
	case CBOR_TYPE_INT:
		DEBUG_EXPR("%li", t.i64);
		return ref && t.i64 == id;
	case CBOR_TYPE_ARRAY:
		for (size_t i = 0; i < t.u32; i++)
			if (has_ref(&t.items[i], id))
				return true;
		return false;
	case CBOR_TYPE_MAP:
		for (size_t i = 0; i < t.u32; i++)
			if (has_ref(&t.pairs[i].key, id) || has_ref(&t.pairs[i].value, id))
				return true;
		return false;
	default:
		return false;
	}
}

/*
 * Check that all records to which `item` holds references exist in the storage.
 */
static bool validate_refs(struct storage *stor, struct cbor_item *item)
{
	struct cbor_item t = *item;
	cbor_tag_t tag;
	bool ref = false;
	while (cbor_item_strip_tag(&t, &tag))
		if (tag == REF_TAG) {
			ref = true;
			break;
		}
	if (ref && t.type == CBOR_TYPE_UINT)
		return storage_get(stor, t.u64) != NULL;
	switch (t.type) {
	case CBOR_TYPE_ARRAY:
		for (size_t i = 0; i < t.u32; i++)
			if (!validate_refs(stor, &t.items[i]))
				return false;
		return true;
	case CBOR_TYPE_MAP:
		for (size_t i = 0; i < t.u32; i++)
			if (!validate_refs(stor, &t.pairs[i].key)
				|| !validate_refs(stor, &t.pairs[i].value))
				return false;
		return true;
	default:
		return true;
	}
}

/*
 * Persist current storage state into a file.
 */
static bool commit(struct dummy *d)
{
	if (!d->path)
		return true;
	bool ret = true;
	char tmpname[] = "fdap-XXXXXX";
	int fd = mkstemp(tmpname);
	if (fd == -1) {
		LOGF(LOG_ERR, "cannot create temporary file '%s': %s", tmpname,
			strerror(errno));
		ret = false;
		goto out;
	}
	struct iobuf *buf = iobuf_sock_new(fd, 4 * 1024);
	struct cbor c;
	cbor_init(&c, buf, cbor_errh_throw);
	try {
		cbor_write_u32(&c, d->base.last_id);
		cbor_write_u32(&c, d->base.version);
		cbor_write_map_start_indef(&c);
		list_walk(d->records, n) {
			struct record *r = container_of(n, struct record, n);
			record_encode(r, &d->base, &c, true);
		}
		cbor_write_map_end(&c);
	} catch {
		LOGF(LOG_ERR, "error while serializing storage to CBOR: %s",
			cbor_strerror(&c));
		ret = false;
		goto out2;
	}
	if (iobuf_flush(buf) != 0) {
		LOG(LOG_ERR, "cannot flush output buffer");
		ret = false;
		goto out2;
	}
	if (rename(tmpname, d->path) != 0) {
		LOGF(LOG_ERR, "cannot move '%s' to '%s': %s", tmpname, d->path,
			strerror(errno));
		ret = false;
		goto out2;
	}
out2:
	cbor_free(&c);
	iobuf_destroy(buf);
	close(fd);
out:
	return ret;
}

/*
 * Load storage state from at `d->path`.
 */
static bool load(struct dummy *d, char *path)
{
	bool ret = true;
	int fd = open(path, O_RDONLY);
	if (fd == -1) {
		LOGF(LOG_ERR, "cannot open file '%s': %s", path,
			strerror(errno));
		ret = false;
		goto out;

	}
	struct iobuf *buf = iobuf_sock_new(fd, 4 * 1024);
	struct cbor c;
	cbor_init(&c, buf, cbor_errh_throw);
	try {
		d->base.last_id = cbor_read_u32(&c);
		d->base.version = cbor_read_u32(&c);
		cbor_read_map_start_indef(&c);
		while (!cbor_read_map_end(&c)) {
			struct record *r = record_decode(&d->base, &c);
			list_insert(&d->records, &r->n);
		}
	} catch {
		LOGF(LOG_ERR, "error while decoding storage data from '%s': %s",
			path, cbor_strerror(&c));
		ret = false;
		goto out2;
	}
	LOGF(LOG_INFO, "Storage loaded successfully from '%s'", path);
out2:
	cbor_free(&c);
	iobuf_destroy(buf);
	close(fd);
out:
	return ret;
}

/*
 * Return true iff there are records in the storage `stor` which hold a
 * reference to record `id` (other than the record itself).
 */
static bool refs_exist(struct storage *stor, record_id_t id)
{
	struct iter *it = storage_walk(stor);
	struct record *r;
	while ((r = iter_next(it)) != NULL) {
		if (r->id == id)
			continue;
		for (size_t i = 0; i < r->nattrs; i++)
			if (has_ref(&r->attrs[i], id)) {
				iter_destroy(it);
				return true;
			}
	}
	iter_destroy(it);
	return false;
}

static storage_result_t _remove(struct storage *stor, record_id_t id)
{
	struct record *old = get(stor, id);
	if (!old)
		return STOR_NXREC;
	if (refs_exist(stor, id))
		return STOR_REFS;
	old->flags |= RECF_OLD;
	struct record *del = record_new(stor, 0);
	del->id = old->id;
	del->version = ++stor->version;
	del->flags = RECF_DEL;
	struct dummy *d = cast(stor);
	list_insert(&d->records, &del->n);
	return commit(d) ? STOR_OK : STOR_COMMIT;
}

static bool is_cbor_undef(struct cbor_item *item)
{
	return item->type == CBOR_TYPE_SVAL && item->sval == CBOR_SVAL_UNDEF;
}

static storage_result_t update(struct storage *stor, struct record *r)
{
	assert(!record_has(r, keystore_key_to_id(&stor->attrs_store, id_attr))); /* TODO move elsewhere */
	for (size_t i = 0; i < r->nattrs; i++)
		if (!validate_refs(stor, &r->attrs[i]))
			return STOR_REFS;
	struct dummy *d = cast(stor);
	size_t new_size = 0; 
	struct record *old = get(stor, r->id);
	if (!old && r->id != RECORD_ID_NONE)
		return STOR_NXREC;
	if (old)
		new_size = old->nattrs;
	new_size += r->nattrs; /* TODO this is impractical overestimate */
	struct record *new = record_dup(stor, old, new_size);
	assert(new != NULL);
	if (old)
		old->flags |= RECF_OLD;
	new->id = old ? old->id : ++stor->last_id;
	new->version = ++stor->version;
	for (size_t i = 0; i < r->nattrs; i++) {
		struct cbor_item *lhs, *rhs = &r->attrs[i];
		if (is_cbor_undef(rhs)) {
			record_remove(new, rhs->u16);
		} else {
			lhs = record_insert(new, rhs->u16);
			assert(lhs != NULL);
			*lhs = *rhs; /* create/override attribute incl. ID (in u16) */
		}
	}
	r->nattrs = 0; /* TODO TODO TODO This is a HORRIBLE hotfix! */
	new->flags |= RECF_NEW;
	if (old)
		new->flags |= RECF_DIRTY;
	new->flags &= ~RECF_NEW; 
	new->flags &= ~RECF_DIRTY; 
	if (old)
		list_insert_after(&d->records, &new->n, &old->n);
	else
		list_insert(&d->records, &new->n);
	return commit(d) ? STOR_OK : STOR_COMMIT;
}

static struct iter *walk(struct storage *stor)
{
	struct dummy *d = cast(stor);
	return iter_new_list(&d->records, stor->version);
}

static void destroy(struct storage *stor)
{
	struct dummy *d = cast(stor);
	list_walk(d->records, n) {
		struct record *r = container_of(n, struct record, n);
		record_destroy(stor, r);
	}
	free(d);
}

static struct storage_ops ops = {
	.update = update,
	.get = get,
	.remove = _remove,
	.walk = walk,
	.search = NULL,
	.destroy = destroy,
};

static bool load_data_seed(struct dummy *d)
{
	struct strbuf seed_path;
	strbuf_init(&seed_path, 128);
	strbuf_printf(&seed_path, "%s.seed", d->path);
	bool res = load(d, strbuf_get_string(&seed_path));
	strbuf_free(&seed_path);
	return res;
}

struct storage *storage_dummy_new(char *path)
{
	struct dummy *d = malloc(sizeof(*d));
	storage_init(&d->base, &ops);
	list_init(&d->records);
	d->path = path;
	if (d->path) {
		load_data_seed(d);
		load(d, d->path);
	};
	return &d->base;
}
