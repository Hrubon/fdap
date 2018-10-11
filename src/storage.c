#include "log.h"
#include "storage.h"

char *id_attr = "@id";
char *types_attr = "@types";

void storage_init(struct storage *stor, struct storage_ops *ops)
{
	stor->ops = ops;
	keystore_init(&stor->attrs_store);
	stor->last_id = RECORD_ID_NONE;
	stor->version = 0;
	/* ensure low IDs for common attrs */
	keystore_key_to_id(&stor->attrs_store, id_attr);
	keystore_key_to_id(&stor->attrs_store, types_attr);
}

void storage_destroy(struct storage *stor)
{
	keystore_free(&stor->attrs_store);
	stor->ops->destroy(stor);
}

struct record *storage_get(struct storage *stor, record_id_t id)
{
	return stor->ops->get(stor, id);
}

storage_result_t storage_update(struct storage *stor, struct record *record)
{
	return stor->ops->update(stor, record);
}

struct iter *storage_walk(struct storage *stor)
{
	return stor->ops->walk(stor);
}

storage_result_t storage_remove(struct storage *stor, record_id_t id)
{
	//assert((record->flags & RECF_DEL) == 0);
	storage_result_t res = stor->ops->remove(stor, id);
	//if (res == STOR_OK)
	//	record->flags |= RECF_DEL;
	return res;
}

struct iter *storage_search(struct storage *stor, struct filter *f)
{
	if (stor->ops->search)
		return stor->ops->search(stor, f);
	return iter_new_filter(storage_walk(stor), f, &stor->attrs_store);
}
