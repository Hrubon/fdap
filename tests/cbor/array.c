#include "cbor.h"
#include <assert.h>

#define IOBUF_INIT_CAPACITY	400
#define INT_ARRAY_SIZE		311

struct iobuf *buf;
struct cbor cbor;

/*
 * Transcode an empty definite-length array.
 */
static void test_empty_array(void)
{
	iobuf_seek(buf, 0);
	cbor_write_array_start_size(&cbor, 0);
	cbor_write_array_end(&cbor);
	iobuf_flush(buf);
	iobuf_seek(buf, 0);
	assert(cbor_read_array_start_size(&cbor) == 0);
	assert(cbor_read_array_end(&cbor));
}

/*
 * Transcode an empty indefinite-length array.
 */
static void test_empty_array_indef(void)
{
	iobuf_seek(buf, 0);
	cbor_write_array_start_indef(&cbor);
	cbor_write_array_end(&cbor);
	iobuf_flush(buf);
	iobuf_seek(buf, 0);
	cbor_read_array_start_indef(&cbor);
	assert(cbor_read_array_end(&cbor));
}

/*
 * Transcode a definite-length array of `INT_ARRAY_SIZE` uints.
 */
static void test_int_array(void)
{
	iobuf_seek(buf, 0);
	cbor_write_array_start_size(&cbor, INT_ARRAY_SIZE);
	for (size_t i = 0; i < INT_ARRAY_SIZE; i++)
		cbor_write_u64(&cbor, i);
	cbor_write_array_end(&cbor);

	iobuf_flush(buf);
	iobuf_seek(buf, 0);
	assert(cbor_read_array_start_size(&cbor) == INT_ARRAY_SIZE);
	for (size_t i = 0; !cbor_read_array_end(&cbor); i++)
		assert(cbor_read_u64(&cbor) == i);

	iobuf_seek(buf, 0);
	cbor_read_array_start(&cbor);
	for (size_t i = 0; !cbor_read_array_end(&cbor); i++)
		assert(cbor_read_u64(&cbor) == i);
}

/*
 * Transcode an indefinite-length array of `INT_ARRAY_SIZE` uints.
 */
static void test_int_array_indef(void)
{
	iobuf_seek(buf, 0);
	cbor_write_array_start_indef(&cbor);
	for (size_t i = 0; i < INT_ARRAY_SIZE; i++)
		cbor_write_u64(&cbor, i);
	cbor_write_array_end(&cbor);

	iobuf_flush(buf);
	iobuf_seek(buf, 0);
	cbor_read_array_start_indef(&cbor);
	for (size_t i = 0; i < INT_ARRAY_SIZE; i++)
		assert(cbor_read_u64(&cbor) == i);
	assert(cbor_read_array_end(&cbor));

	iobuf_seek(buf, 0);
	cbor_read_array_start(&cbor);
	for (size_t i = 0; i < INT_ARRAY_SIZE; i++)
		assert(cbor_read_u64(&cbor) == i);
	assert(cbor_read_array_end(&cbor));
}

static void test_nested_arrays(void)
{
	iobuf_seek(buf, 0);
	cbor_write_array_start_indef(&cbor);
	cbor_write_array_start_indef(&cbor);
	cbor_write_array_start_size(&cbor, 2);
	cbor_write_array_start_size(&cbor, 0);
	cbor_write_array_end(&cbor);
	cbor_write_array_start_indef(&cbor);
	cbor_write_array_end(&cbor);
	cbor_write_array_end(&cbor);
	cbor_write_array_end(&cbor);
	cbor_write_array_end(&cbor);
	iobuf_flush(buf);
	iobuf_seek(buf, 0);

	cbor_read_array_start_indef(&cbor); /* open 1st indef */
	cbor_read_array_start_indef(&cbor); /* open 2nd indef */
	assert(cbor_read_array_start_size(&cbor) == 2); /* open size 2 */
	assert(cbor_read_array_start_size(&cbor) == 0); /* first item, size 0 */
	assert(cbor_read_array_end(&cbor)); /* end it */
	cbor_read_array_start_indef(&cbor); /* second item, size 0 indef */
	assert(cbor_read_array_end(&cbor)); /* end it */
	assert(cbor_read_array_end(&cbor)); /* end size 2 */
	assert(cbor_read_array_end(&cbor)); /* end 2nd indef */
	assert(cbor_read_array_end(&cbor)); /* end 1st indef */
}

int main(void)
{
	buf = iobuf_str_new(IOBUF_INIT_CAPACITY);
	cbor_init(&cbor, buf, cbor_errh_default);

	test_empty_array();
	test_empty_array_indef();
	test_int_array();
	test_int_array_indef();
	test_nested_arrays();

	cbor_free(&cbor);
	iobuf_destroy(buf);
	return EXIT_SUCCESS;
}
