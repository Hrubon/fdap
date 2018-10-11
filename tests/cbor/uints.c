#include "cbor.h"
#include "debug.h"
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define UINT_WINDOW		4251UL
#define IOBUF_INIT_CAPACITY	400

struct iobuf *buf;
struct cbor cbor;

/*
 * Try transcode uints in the interval [first, last).
 */
static void test_uints_range(uint64_t first, uint64_t last)
{
	assert(first < last);
	iobuf_seek(buf, 0);
	for (uint64_t i = first; i < last; i++)
		cbor_write_u64(&cbor, i);
	iobuf_flush(buf);
	iobuf_seek(buf, 0);
	for (uint64_t i = first; i < last; i++)
		assert(cbor_read_u64(&cbor) == i);
}

int main(void)
{
	buf = iobuf_str_new(IOBUF_INIT_CAPACITY);
	cbor_init(&cbor, buf, cbor_errh_default);

	test_uints_range(0, 23);
	test_uints_range(0, UINT16_MAX);
	test_uints_range(UINT32_MAX - UINT_WINDOW, UINT32_MAX + UINT_WINDOW);
	test_uints_range(UINT64_MAX - UINT_WINDOW, UINT64_MAX);

	cbor_free(&cbor);
	iobuf_destroy(buf);
	return EXIT_SUCCESS;
}
