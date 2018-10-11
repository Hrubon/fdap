#include "keystore.h"
#include <assert.h>
#include <string.h>

#define FOO	"foo"
#define BAR	"bar"

int main(void)
{
	struct keystore store;
	keystore_init(&store);

	assert(keystore_key_to_id(&store, FOO) == 0);
	assert(keystore_key_to_id(&store, BAR) == 1);

	assert(strcmp(keystore_id_to_key(&store, 0), FOO) == 0);
	assert(strcmp(keystore_id_to_key(&store, 1), BAR) == 0);

	keystore_free(&store);
	return 0;
}
