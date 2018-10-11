#include "cbor.h"
#include "test.h"

#define IOBUF_INIT_CAPACITY	400

struct iobuf *buf;
struct cbor cbor;

/*
 * Try transcode tags in the interval [first, last).
 */
static void test_tags_range(uint64_t first, uint64_t last)
{
	assert(first < last);
	iobuf_seek(buf, 0);
	for (uint64_t tag = first; tag < last; tag++)
		cbor_write_tag(&cbor, tag);
	iobuf_flush(buf);
	iobuf_seek(buf, 0);
	for (uint64_t tag = first; tag < last; tag++)
		assert(cbor_read_tag(&cbor) == tag);
}

/*
 * Try to read a tag which exceeds implementation-defined maximum.
 */
static void test_tag_overflow(void)
{
	iobuf_seek(buf, 0);
	iobuf_write(buf, (byte_t[]){ 0xDB }, 1);
	uint64_t big_tag_be = htobe64(CBOR_TAG_MAX + 1UL);
	iobuf_write(buf, (byte_t *)&big_tag_be, sizeof(big_tag_be));
	iobuf_flush(buf);
	iobuf_seek(buf, 0);
	try {
		(void) cbor_read_tag(&cbor);
		assert_unreachable();
	}
}

int main(void)
{
	buf = iobuf_str_new(IOBUF_INIT_CAPACITY);
	cbor_init(&cbor, buf, errh_throw);

	try {
		test_tags_range(0, UINT16_MAX);
		test_tags_range(CBOR_TAG_MAX - 1024, CBOR_TAG_MAX + 1UL);
	} catch {
		assert_unreachable();
	}

	test_tag_overflow();

	cbor_free(&cbor);
	iobuf_destroy(buf);
	return EXIT_SUCCESS;
}
