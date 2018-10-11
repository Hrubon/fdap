#include "cbor.h"
#include <assert.h>

#define IOBUF_INIT_CAPACITY	400
#define INT_MAP_SIZE		224

struct iobuf *buf;
struct cbor cbor;

/*
 * Transcode an empty definite-length map.
 */
static void test_empty_map(void)
{
	iobuf_seek(buf, 0);
	cbor_write_map_start_size(&cbor, 0);
	cbor_write_map_end(&cbor);
	iobuf_flush(buf);
	iobuf_seek(buf, 0);
	assert(cbor_read_map_start_size(&cbor) == 0);
	assert(cbor_read_map_end(&cbor));
}

/*
 * Transcode an empty indefinite-length map.
 */
static void test_empty_map_indef(void)
{
	iobuf_seek(buf, 0);
	cbor_write_map_start_indef(&cbor);
	cbor_write_map_end(&cbor);
	iobuf_flush(buf);
	iobuf_seek(buf, 0);
	cbor_read_map_start_indef(&cbor);
	assert(cbor_read_map_end(&cbor));
}

static void test_int_map(void)
{
	iobuf_seek(buf, 0);
	cbor_write_map_start_size(&cbor, INT_MAP_SIZE);
	for (size_t i = 0; i < INT_MAP_SIZE; i++) {
		cbor_write_u64(&cbor, i);
		cbor_write_u64(&cbor, i + 1);
	}
	cbor_write_map_end(&cbor);
	iobuf_flush(buf);
	iobuf_seek(buf, 0);
	assert(cbor_read_map_start_size(&cbor) == INT_MAP_SIZE);
	for (size_t i = 0; i < INT_MAP_SIZE; i++) {
		assert(cbor_read_u64(&cbor) == i);
		assert(cbor_read_u64(&cbor) == i + 1);
	}
	assert(cbor_read_map_end(&cbor));
}

void cbor_stream_print_scopes(struct cbor *cs);

static void test_nested_maps(void)
{
	iobuf_seek(buf, 0);
	cbor_write_map_start_indef(&cbor); /* 1st indef */
	cbor_write_map_start_size(&cbor, 1); /* outer size 1 */
	cbor_write_map_start_size(&cbor, 0); /* key in outer size 1 */
	cbor_write_map_end(&cbor); /* end it */
	cbor_write_map_start_indef(&cbor); /* 2nd indef, value in outer size 1 */
	cbor_write_map_start_size(&cbor, 2); /* size 2, key in 2nd indef */
	cbor_write_map_start_size(&cbor, 0); /* 1st key in size 2 */
	cbor_write_map_end(&cbor); /* end it */
	cbor_write_map_start_indef(&cbor); /* 1st value in size */
	cbor_write_map_end(&cbor); /* end it */
	cbor_write_map_start_size(&cbor, 0); /* 2nd key in size 2 */
	cbor_write_map_end(&cbor); /* end it */
	cbor_write_map_start_size(&cbor, 0); /* 2nd value in size 2 */
	cbor_write_map_end(&cbor); /* end it */
	cbor_write_map_end(&cbor); /* end size 2 */
	cbor_write_map_end(&cbor); /* end 2nd indef */
	cbor_write_map_end(&cbor); /* end outer size 1 */
	cbor_write_map_end(&cbor); /* end 1st indef */

	iobuf_flush(buf);
	iobuf_seek(buf, 0);
	cbor_read_map_start_indef(&cbor);
	assert(cbor_read_map_start_size(&cbor) == 1);
	assert(cbor_read_map_start_size(&cbor) == 0);
	assert(cbor_read_map_end(&cbor));
	cbor_read_map_start_indef(&cbor);
	assert(cbor_read_map_start_size(&cbor) == 2);
	assert(cbor_read_map_start_size(&cbor) == 0);
	assert(cbor_read_map_end(&cbor));
	cbor_read_map_start_indef(&cbor);
	assert(cbor_read_map_end(&cbor));
	assert(cbor_read_map_start_size(&cbor) == 0);
	assert(cbor_read_map_end(&cbor));
	assert(cbor_read_map_start_size(&cbor) == 0);
	assert(cbor_read_map_end(&cbor));
	assert(cbor_read_map_end(&cbor));
	assert(cbor_read_map_end(&cbor));
	assert(cbor_read_map_end(&cbor));
	assert(cbor_read_map_end(&cbor));
}

static void test_int_map_indef(void)
{
	iobuf_seek(buf, 0);
	cbor_write_map_start_indef(&cbor);
	for (size_t i = 0; i < INT_MAP_SIZE; i++) {
		cbor_write_u64(&cbor, i);
		cbor_write_u64(&cbor, i + 1);
	}
	cbor_write_map_end(&cbor);
	iobuf_flush(buf);
	iobuf_seek(buf, 0);
	cbor_read_map_start_indef(&cbor);
	for (size_t i = 0; i < INT_MAP_SIZE; i++) {
		assert(cbor_read_u64(&cbor) == i);
		assert(cbor_read_u64(&cbor) == i + 1);
	}
	assert(cbor_read_map_end(&cbor));
}

int main(void)
{
	buf = iobuf_str_new(IOBUF_INIT_CAPACITY);
	cbor_init(&cbor, buf, cbor_errh_default);

	test_empty_map();
	test_empty_map_indef();
	test_int_map();
	test_nested_maps();

	cbor_free(&cbor);
	iobuf_destroy(buf);
	return EXIT_SUCCESS;
}
