#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include "debug.h"
#include "diag.h"

#define STRBUF_INIT_SIZE	128

static bool test_diag_build(char *target, char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	struct cbor_item item;
	if (!diag_build(&item, fmt, args))
		return false;
	struct strbuf buf;
	strbuf_init(&buf, STRBUF_INIT_SIZE);
	cbor_item_dump(&item, &buf);
	char *diag = strbuf_get_string(&buf);
	DEBUG_EXPR("%s", target);
	DEBUG_EXPR("  %s", diag);
	int ret = strcmp(target, diag);
	strbuf_free(&buf);
	cbor_item_free(&item);
	va_end(args);
	return ret == 0;
}


int main(void)
{
	assert(test_diag_build("520", "%i", 520));
	assert(test_diag_build("'ahoj svete'", "%s", "ahoj svete"));
	assert(test_diag_build("{'username': 'Johny \\'The Devil\\' Smith', 'age': 56}",
		"{username: %s, age: %i}", "Johny 'The Devil' Smith", 56));
	assert(test_diag_build("simple(36)", "%v", 36));
	assert(test_diag_build("true", "%b", true));
	assert(test_diag_build("{'simplex': 50}", "{simplex: %i}", 50));
}
