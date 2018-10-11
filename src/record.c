#include "debug.h"
#include "record.h"
#include "strbuf.h"
#include <assert.h>
#include "storage.h"
#include <string.h>

#define ANAME_BLOCK_SIZE	32

static size_t alloc_size(nattrs_t size)
{
	return sizeof(struct record) + sizeof(struct cbor_item) * (size - 1); 
}

void record_init(struct record *rec)
{
	rec->id = 0;
	rec->version = 0;
	rec->size = 0;
	rec->nattrs = 0;
	rec->flags = 0;
}

struct record *record_new(struct storage *stor, nattrs_t size)
{
	(void) stor;
	struct record *rec = malloc(alloc_size(size));
	record_init(rec);
	rec->size = size;
	return rec;
}

struct record *record_dup(struct storage *stor, struct record *orig, nattrs_t new_size)
{
	size_t old_nattrs = 0;
	if (orig != NULL)
		old_nattrs = orig->nattrs;
	assert(new_size >= old_nattrs);
	struct record *dup = record_new(stor, new_size);
	if (orig != NULL)
		memcpy(dup, orig, alloc_size(old_nattrs));
	dup->size = new_size;
	return dup;
}

void record_destroy(struct storage *stor, struct record *rec)
{
	(void) stor;
	for (size_t i = 0; i < rec->nattrs; i++)
		cbor_item_free(&rec->attrs[i]);
	free(rec);
}

void record_dump(struct record *rec, struct strbuf *buf)
{
	strbuf_printf(buf, "RECORD(");
	if (rec->id == RECORD_ID_NONE)
		strbuf_printf(buf, "ID=<none>");
	else
		strbuf_printf(buf, "ID=%i", rec->id);
	if (rec->flags) {
		strbuf_printf(buf, ", flags=");
		if (rec->flags & RECF_NEW)
			strbuf_putc(buf, 'N');
		if (rec->flags & RECF_DIRTY)
			strbuf_putc(buf, 'd');
		if (rec->flags & RECF_DEL)
			strbuf_putc(buf, 'D');
		if (rec->flags & RECF_OLD)
			strbuf_putc(buf, 'o');
	}
	strbuf_printf(buf, ", attrs={");
	for (size_t i = 0; i < rec->nattrs; i++) {
		if (i > 0)
			strbuf_printf(buf, ", ");
		strbuf_printf(buf, "%i: ", rec->attrs[i].u16);
		cbor_item_dump(&rec->attrs[i], buf);
	}
	strbuf_printf(buf, "})");
}

bool record_has(struct record *rec, key_id_t id)
{
	return record_getby_id(rec, id) != NULL;
}

static size_t bsearch_attr(struct record *rec, key_id_t id)
{
	size_t l = 0, r = rec->nattrs;
	while (l < r) {
		size_t m = (l + r) / 2;
		if (rec->attrs[m].u16 <= id)
			r = m;
		else
			l = m + 1;
	}
	return l;
}

/*
 * Get value of the attribute with the name `n` taken from `offset`, from `item`.
 * The name `n` is a in-memory component representation of the attribute name.
 * First `offset` components of the attribute name will be omited.
 */
static struct cbor_item *get_attr(struct cbor_item *item, struct aname *n, size_t offset)
{
	for (size_t i = offset; item && i < n->nparts; i++) {
		if (item->type != CBOR_TYPE_MAP)
			return NULL;
		bool found = false;
		for (size_t j = 0; j < item->u32; j++) {
			struct cbor_pair *p = &item->pairs[j];
			if (p->key.type != CBOR_TYPE_TEXT)
				continue;
			if (strcmp(cbor_item_get_text(&p->key), n->parts[i]) != 0)
				continue;
			item = &p->value;
			found = true;
			break;
		}
		if (!found)
			return NULL;
	}
	return item;
}

struct cbor_item *record_getby_id(struct record *rec, key_id_t id)
{
	size_t idx = bsearch_attr(rec, id);
	if (idx < rec->nattrs && rec->attrs[idx].u16 == id)
		return &rec->attrs[idx];
	return NULL;
}

struct cbor_item *record_getby_name(struct record *r, char *dotname)
{
	struct mempool mp;
	mempool_init(&mp, ANAME_BLOCK_SIZE);
	struct aname *n = aname_new(dotname, &mp);
	struct cbor_item *item = get_attr(r->attrs, n, 0);
	mempool_free(&mp);
	return item;
}

struct cbor_item *record_getby_name_keys(struct record *r, char *dotname, struct keystore *keys)
{
	struct mempool mp;
	mempool_init(&mp, 16);
	struct aname *n = aname_new(dotname, &mp);
	struct cbor_item *item = record_getby_aname(r, n, keys);
	mempool_free(&mp);
	return item;
}

struct cbor_item *record_getby_aname(struct record *r, struct aname *n, struct keystore *keys)
{
	assert(n->nparts >= 1);
	key_id_t id = keystore_key_to_id(keys, n->parts[0]);
	struct cbor_item *item = record_getby_id(r, id);
	return get_attr(item, n, 1);
}

bool record_get_int(struct record *r, char *dotname, int *val)
{
	struct cbor_item *item = record_getby_name(r, dotname);
	if (!item)
		return false;
	if (item->type == CBOR_TYPE_UINT) {
		*val = item->u64;
		return true;
	} else if (item->type == CBOR_TYPE_INT) {
		*val = item->i64;
		return true;
	}
	return false;
}

bool record_get_string(struct record *r, char *dotname, char **val)
{
	struct cbor_item *item = record_getby_name(r, dotname);
	if (!item)
		return false;
	if (item->type == CBOR_TYPE_TEXT) {
		*val = cbor_item_get_text(item);
		return true;
	}
	return false;
}

bool record_get_bool(struct record *r, char *dotname, bool *val)
{
	struct cbor_item *item = record_getby_name(r, dotname);
	if (!item)
		return false;
	if (item->type == CBOR_TYPE_SVAL) {
		if (item->sval == CBOR_SVAL_FALSE) {
			*val = false;
			return true;
		} else if (item->sval == CBOR_SVAL_TRUE) {
			*val = true;
			return true;
		}
	}
	return false;
}

struct cbor_item *record_to_item(struct record *r)
{
	return r->attrs;
}

struct cbor_item *record_insert(struct record *rec, key_id_t id)
{
	size_t idx = bsearch_attr(rec, id);
	if (idx < rec->nattrs && rec->attrs[idx].u16 == id)
		return &rec->attrs[idx]; /* already have it */
	if (rec->nattrs == rec->size)
		return NULL; /* record full */
	memmove(rec->attrs + idx + 1, rec->attrs + idx, sizeof(*rec->attrs) * (rec->nattrs - idx));
	rec->attrs[idx].u16 = id;
	rec->nattrs++;
	rec->flags |= RECF_DIRTY;
	return &rec->attrs[idx];
}

bool record_remove(struct record *rec, key_id_t id)
{
	size_t idx = bsearch_attr(rec, id);
	if (idx >= rec->nattrs || rec->attrs[idx].u16 != id)
		return false; /* attribute not found */
	rec->nattrs--;
	memmove(rec->attrs + idx, rec->attrs + idx + 1, sizeof(*rec->attrs) * (rec->nattrs - idx));
	rec->flags |= RECF_DIRTY;
	return true;
}

void record_encode(struct record *rec, struct storage *stor, struct cbor *c, bool full)
{
	cbor_write_u32(c, rec->id);
	cbor_write_u32(c, rec->version);
	if (full)
		cbor_write_u8(c, rec->flags);
	cbor_write_map_start_size(c, rec->nattrs);
	for (size_t i = 0; i < rec->nattrs; i++) {
		key_id_t id = rec->attrs[i].u16;
		char *key = keystore_id_to_key(&stor->attrs_store, id);
		cbor_write_text(c, key);
		cbor_write_item(c, &rec->attrs[i]);
	}
	cbor_write_map_end(c);
}

struct record *record_decode(struct storage *stor, struct cbor *c)
{
	record_id_t id = cbor_read_u32(c);
	version_t version = cbor_read_u32(c);
	uint8_t flags = cbor_read_u8(c);
	size_t nattrs = cbor_read_map_start_size(c);
	struct record *rec = record_new(stor, nattrs);
	rec->id = id;
	rec->version = version;
	rec->flags = flags;
	char *key;
	for (size_t i = 0; i < nattrs; i++) {
		(void) cbor_read_text_alloc(c, &key);
		key_id_t id = keystore_key_to_id(&stor->attrs_store, key);
		cbor_read_item(c, record_insert(rec, id));
		free(key);
	}
	cbor_read_map_end(c);
	rec->flags &= ~RECF_DIRTY; /* hotfix */
	return rec;
}
