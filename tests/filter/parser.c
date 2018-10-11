#include <assert.h>
#include <string.h>
#include "filter.h"
#include "log.h"
#include "strbuf.h"

#define STRBUF_INIT_SIZE	1024

static int test_filter(const char *filter_str)
{
	struct strbuf buf;

	strbuf_init(&buf, STRBUF_INIT_SIZE);
	struct filter f;
	int ret = filter_parse_string(&f, filter_str);
	if (!ret) {
		filter_dump(&f, &buf);
		char *out_str = strbuf_get_string(&buf);
		DEBUG_EXPR("%s", filter_str);
		DEBUG_EXPR("%s", out_str);
		assert(strcmp(out_str, filter_str) == 0);
		LOGF(LOG_INFO, "Test passed, filter: %s", out_str);
	}
	filter_free(&f);
	strbuf_free(&buf);
	return ret;
}


int main(void)
{
	int ret;

	char *f1 = "user.name > 100";
	ret = test_filter(f1);
	assert(ret == 0);

	char *f2 = "= xyz >= 100";
	ret = test_filter(f2);
	assert(ret != 0);

	char *f3 = "((a > 50 & b = 'foo') | c != null)";
	ret = test_filter(f3);
	assert(ret == 0);

	char *f4 = "user.foo = 'Johny \\\'The Devil\\\' Smith'";
	ret = test_filter(f4);
	assert(ret == 0);

	char *f5 = "x = '\\\\ makes me crazy! \\\\''";
	ret = test_filter(f5);
	assert(ret != 0);

	char *f6 = "x = simple(52)";
	ret = test_filter(f6);
	assert(ret == 0);
}
