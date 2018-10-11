#include "cbor.h"
#include "array.h"
#include "debug.h"
#include <assert.h>
#include <stdlib.h>
#include <time.h>

#define IOBUF_INIT_CAPACITY	400
#define ARRAY_MAX_SIZE		8
#define MAP_MAX_SIZE		8
#define TEXT_MAX_LEN		32
#define BYTES_MAX_LEN		32
#define MAX_DEPTH		4
#define TEST_SIZE		256

struct iobuf *buf;
struct cbor cbor;

static void write_random_text_chunk(void)
{
	size_t len = rand() % TEXT_MAX_LEN;
	char str[len + 1];
	for (size_t i = 0; i < len; i++)
		str[i] = 'a' + rand() % 25;
	str[len] = '\0';
	cbor_write_text(&cbor, str);
}

static void write_random_bytes_chunk(void)
{
	size_t len = rand() % BYTES_MAX_LEN;
	byte_t bytes[len];
	for (size_t i = 0; i < len; i++)
		bytes[i] = rand() % 256;
	cbor_write_bytes(&cbor, bytes, len);
}

static void write_random_item(size_t depth);

static void write_random_array(size_t depth)
{
	size_t size = rand() % ARRAY_MAX_SIZE;
	cbor_write_array_start_size(&cbor, size);
	for (size_t i = 0; i < size; i++)
		write_random_item(depth + 1);
	cbor_write_array_end(&cbor);
}

static void write_random_map(size_t depth)
{
	size_t size = rand() % MAP_MAX_SIZE;
	cbor_write_map_start_size(&cbor, size);
	for (size_t i = 0; i < 2 * size; i++)
		write_random_item(depth + 1);
	cbor_write_map_end(&cbor);
}

static void write_random_item(size_t depth)
{
again:
	switch (rand() % 8) {
	case CBOR_TYPE_UINT:
		cbor_write_u64(&cbor, rand());
		break;
	case CBOR_TYPE_INT:
		cbor_write_i64(&cbor, (rand() % 2) ? rand() : -rand());
		break;
	case CBOR_TYPE_TEXT:
		write_random_text_chunk();
		break;
	case CBOR_TYPE_BYTES:
		write_random_bytes_chunk();
		break;
	case CBOR_TYPE_ARRAY:
		if (depth == MAX_DEPTH)
			goto again;
		write_random_array(depth);
		break;
	case CBOR_TYPE_MAP:
		if (depth == MAX_DEPTH)
			goto again;
		write_random_map(depth);
		break;
	default:
		goto again;
	}
}

static void free_item(struct cbor_item *item)
{
	cbor_item_free(item);
}

#include "strbuf.h"

int main(void)
{
	buf = iobuf_str_new(IOBUF_INIT_CAPACITY);
	cbor_init(&cbor, buf, cbor_errh_default);
	srand(time(NULL));

	for (size_t i = 0; i < TEST_SIZE; i++) {
		iobuf_seek(buf, 0);
		write_random_item(0);
		iobuf_flush(buf);
		iobuf_seek(buf, 0);

		struct cbor_item i1;
		cbor_read_item(&cbor, &i1);
		
		iobuf_seek(buf, 0);
		cbor_write_item(&cbor, &i1);

		iobuf_seek(buf, 0);
		struct cbor_item i2;
		cbor_read_item(&cbor, &i2);

		if (cbor_item_cmp(&i1, &i2)) {
			struct strbuf diag;
			strbuf_init(&diag, 128);
			cbor_item_dump(&i1, &diag);
			fprintf(stderr, "Item #1: %s\n", strbuf_get_string(&diag));
			strbuf_reset(&diag);
			cbor_item_dump(&i2, &diag);
			fprintf(stderr, "Item #2: %s\n", strbuf_get_string(&diag));
			strbuf_free(&diag);
		}

		assert(cbor_item_cmp(&i1, &i2) == 0);

		free_item(&i1);
		free_item(&i2);
	}

	cbor_free(&cbor);
	iobuf_destroy(buf);
	return EXIT_SUCCESS;
}
