#include "diag.h"
#include "debug.h"
#include "log.h"
#include <string.h>
#include <assert.h>

static char *xcode[] = {
	"'ahoj'",
	"b'af53D0c'",
	"0123",
	"[1]",
	"-77",
	"+420",
	"{'a': 'b', 'age': 77, '@refs': [0, 1, 2]}",
	"{bare: true, 'string': 'value'}",
	"{abc: test}",
	"b'f6'",
	"{tagged: (2)7, arr: ['a', 2, 3] }",
	"{@id: 7}",
	"{ 'a ' :'b  ',  }",
	"'He said: \\'I know her \\\\ him\\''",
	NULL,
};

static char *xcode_err[] = {
	"567h4g",
	"'ahoj''",
	"'svete\\'",
	" b 'f6'",
	"[ true false ]",
	"{ a:	'test'	b: 53 }",
	"b'kb32'",
	NULL,
};

static void test_sample(char **sample, bool ref)
{
	for (size_t i = 0; sample[i]; i++) {
		DEBUG_EXPR("%s", sample[i]);
		/* need to create new buffer every time, no iobuf_trunc support TODO */
		struct iobuf *str = iobuf_str_new(128);
		iobuf_flush(str);
		iobuf_seek(str, 0);
		assert(iobuf_write(str, (byte_t *)sample[i], strlen(sample[i])) == 0);
		iobuf_seek(str, 0);
		struct diag_parser p;
		diag_parser_init(&p, str);
		struct cbor_item root_item;
		bool ret = diag_parse(&p, &root_item);
		assert(ret == ref);
		diag_parser_free(&p);
		iobuf_destroy(str);
		cbor_item_free(&root_item);
		LOGF(LOG_INFO, "Test #%u passed", i + 1);
	}
}

int main(void)
{
	test_sample(xcode, true);
	test_sample(xcode_err, false);
	return 0;
}
