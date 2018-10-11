#include "storage.h"
#include "filter.h"
#include <assert.h>

struct storage *stor;

int main(void)
{
	stor = storage_dummy_new(NULL);
	struct record *r = record_new(stor, 1);
	struct cbor_item *item = record_insert(r, keystore_key_to_id(&stor->attrs_store, "number"));
	cbor_item_set_int(item, 10);
	struct filter f;
	assert(filter_parse_string(&f, "number = 10") == 0);
	assert(filter_match(&f, r, &stor->attrs_store));
	filter_free(&f);
	record_destroy(stor, r);
	storage_destroy(stor);
	return 0;
}
