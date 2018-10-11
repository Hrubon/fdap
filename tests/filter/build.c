#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include "debug.h"
#include "filter.h"

#define STRBUF_INIT_SIZE	128

static bool test_filter_build(char *target, char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	struct filter f;
	if (!filter_vbuild(&f, fmt, args))
		return false;
	struct strbuf buf;
	strbuf_init(&buf, STRBUF_INIT_SIZE);
	filter_dump(&f, &buf);
	char *filter = strbuf_get_string(&buf);
	DEBUG_EXPR("%s", filter);
	int ret = strcmp(target, filter);
	strbuf_free(&buf);
	filter_free(&f);
	va_end(args);
	return ret == 0;
}


int main(void)
{
	assert(test_filter_build("a > 250", "a > %i", 250));
	assert(test_filter_build("(b = false & (x.a < 500 | y = 'ahoj'))",
		"(b = %b & (x.a < %i | y = %s))", false, 500, "ahoj"));
	assert(test_filter_build("(a > 250 | b = '100%')", "(a > %i | b = '100%%')", 250));

	struct filter f;
	assert(filter_parse_string(&f, "x = simple(52) & y < 30") == 0);
	assert(test_filter_build("(a != 'test' | (x = simple(52) & y < 30))", "(a != %s | %f)", "test", &f));
	filter_free(&f);

	return 0;
}
