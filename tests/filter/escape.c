#include <string.h>
#include "cbor.h"
#include "debug.h"
#include "fdap.h"
#include "log.h"
#include "strbuf.h"

#define STRBUF_INIT_LEN		128

static void test_string_escape(char *target, char *str)
{
	struct strbuf buf;
	strbuf_init(&buf, STRBUF_INIT_LEN);
	size_t written = cbor_text_escape(str, &buf);
	char *escape = strbuf_get_string(&buf);
	DEBUG_EXPR("%s", target);
	DEBUG_EXPR("%s", escape);
	DEBUG_EXPR("%lu", strlen(target));
	DEBUG_EXPR("%lu", written);
	DEBUG_MSG("");
	assert(strcmp(target, escape) == 0);
	assert(strlen(target) == written);
	strbuf_free(&buf);
}

static void test_string_unescape(char *target, char *str)
{
	char *s = strdup(str);
	char *unesc = cbor_text_unescape(s);
	DEBUG_EXPR("%s", target);
	DEBUG_EXPR("%s", unesc);
	DEBUG_EXPR("%lu", strlen(target));
	DEBUG_EXPR("%lu", strlen(unesc));
	DEBUG_MSG("");
	assert(strcmp(target, unesc) == 0);
	free(s);
}

int main(void)
{
	test_string_escape("'He said: \\'Give it to me!\\''", "He said: 'Give it to me!'");
	test_string_escape("'\\\\\\\\'", "\\\\\\");
	test_string_escape("'\\\\a\\\\\\''", "\\a\\\\'");
	test_string_escape("''", "");

	test_string_unescape("Hello, there", "'Hello, there'");
	test_string_unescape("Title: 'Welcome'", "'Title: \'Welcome\''");
	test_string_unescape("'\\'\\", "'\\'\\\\\\'\\\\'");
	test_string_unescape("", "''");
}
