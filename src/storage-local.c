#include "common.h"
#include "storage.h"

struct storage_local
{
	struct storage base;
};

static struct storage_local *cast(struct storage *stor)
{
	return container_of(stor, struct storage_local, base);
}

static storage_result_t update(struct storage *stor, struct record *record)
{
	(void) stor;
	(void) record;
	return STOR_OK;
}

static struct record *get(struct storage *stor, record_id_t id)
{
	(void) stor;
	(void) id;
	return NULL;
}

static storage_result_t _remove(struct storage *stor, record_id_t id)
{
	(void) stor;
	(void) id;
	return STOR_OK;
}

static void destroy(struct storage *stor)
{
	free(cast(stor));
}

static struct storage_ops ops = {
	.update = update,
	.get = get,
	.remove = _remove,
	.destroy = destroy,
};

struct storage *storage_local_new(void)
{
	struct storage_local *local = malloc(sizeof(*local));
	storage_init(&local->base, &ops);
	return &local->base;
}
