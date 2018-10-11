#include "cbor.h"
#include "debug.h"
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define INT_WINDOW		5237L
#define IOBUF_INIT_CAPACITY	400

struct iobuf *buf;
struct cbor cbor;

/*
 * Try transcode ints in the interval [first, last).
 */
static void test_ints_range(int64_t first, int64_t last)
{
	assert(first < last);
	iobuf_seek(buf, 0);
	for (int64_t i = first; i < last; i++)
		cbor_write_i64(&cbor, i);
	iobuf_flush(buf);
	iobuf_seek(buf, 0);
	for (int64_t i = first; i < last; i++)
		assert(cbor_read_i64(&cbor) == i);
}

int main(void)
{
	buf = iobuf_str_new(IOBUF_INIT_CAPACITY);
	cbor_init(&cbor, buf, cbor_errh_default);

	test_ints_range(-24, 0);
	test_ints_range(INT16_MIN, 0);
	test_ints_range(INT32_MIN - INT_WINDOW, INT32_MIN + 1024L);
	test_ints_range(INT64_MIN, INT64_MIN + INT_WINDOW);

	cbor_free(&cbor);
	iobuf_destroy(buf);
	return EXIT_SUCCESS;
}
