#include "cbor.h"
#include "debug.h"
#include <assert.h>
#include "memory.h"
#include <time.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define IOBUF_INIT_CAPACITY	400
#define STRBUF_INIT_SIZE	128
#define NUM_CHUNKS		17

struct iobuf *buf;
struct cbor cbor;
byte_t *chunks[NUM_CHUNKS];
size_t chunk_len[NUM_CHUNKS];

/*
 * Write a definite-length byte stream, read it using `cbor_read_bytes_alloc`.
 */
static void test_bytes_alloc(byte_t *stream, size_t len)
{
	iobuf_seek(buf, 0);
	cbor_write_bytes(&cbor, stream, len);
	iobuf_flush(buf);
	iobuf_seek(buf, 0);
	byte_t *ret;
	size_t ret_len = cbor_read_bytes_alloc(&cbor, &ret);
	assert(len == ret_len);
	cbor_bytes_destroy(&cbor, ret);
}

static size_t write_chunked_bytes(byte_t **lbytes)
{
	cbor_write_bytes_start_indef(&cbor);
	size_t total_len = 0;
	for (size_t i = 0; i < NUM_CHUNKS; i++) {
		cbor_write_bytes(&cbor, chunks[i], chunk_len[i]);
		total_len += chunk_len[i];
	}
	*lbytes = fdap_malloc(total_len);
	size_t len = 0;
	for (size_t i = 0; i < NUM_CHUNKS; i++) {
		memcpy(&(*lbytes)[len], chunks[i], chunk_len[i]);
		len += chunk_len[i];
	}
	cbor_write_bytes_end(&cbor);
	return total_len;
}

/*
 * Write an indefinite-length byte stream composed of several chunks. Then
 * use `cbor_read_bytes_alloc` to allocate it in and read it into memory.
 */
static void test_bytes_alloc_2(void)
{
	iobuf_seek(buf, 0);
	byte_t *lbytes;
	size_t total_len = write_chunked_bytes(&lbytes);
	iobuf_flush(buf);
	iobuf_seek(buf, 0);
	byte_t *ret;
	size_t ret_len = cbor_read_bytes_alloc(&cbor, &ret);
	assert(ret_len == total_len);
	cbor_bytes_destroy(&cbor, ret);
	free(lbytes);
}

/*
 * Write an indefinite-length byte stream composed of several chunks. Then
 * start reading this stream using `cbor_read_byte_start_indef` and consume
 * the content of the whole logical stream using `cbor_read_bytes`.
 */
static void test_chunked_bytes(size_t buf_size)
{
	iobuf_seek(buf, 0);
	byte_t *lbytes;
	size_t total_len = write_chunked_bytes(&lbytes);
	iobuf_flush(buf);
	iobuf_seek(buf, 0);
	
	byte_t buf[buf_size];
	cbor_read_bytes_start_indef(&cbor);
	size_t size = 0;
	size_t len = 0;
	size_t offset = 0;
	byte_t *rbytes = NULL;
	while (!cbor_read_bytes_end(&cbor)) {
		size_t nread = cbor_read_bytes(&cbor, buf, buf_size);
		len += nread;
		if (len > size) {
			size = 2 * len;
			rbytes = realloc(rbytes, size);
		}
		memcpy(&rbytes[offset], buf, nread);
		offset += nread;
	}
	assert(len == total_len);
	assert(memcmp(lbytes, rbytes, len) == 0);
	free(lbytes);
	free(rbytes);
}

/*
 * Write an indefinite-length byte stream composed of several chunks. Then start
 * reading this stream using `cbor_read_bytes_start_indef`. Start reading each
 * chunk in the text stream explicitly using `cbor_read_bytes_start_len` and
 * consume it using `cbor_read_bytes`.
 */
static void test_chunked_bytes_2(size_t buf_size)
{
	iobuf_seek(buf, 0);
	byte_t *lbytes;
	size_t total_len = write_chunked_bytes(&lbytes);
	iobuf_flush(buf);
	iobuf_seek(buf, 0);

	byte_t buf[buf_size];
	cbor_read_bytes_start_indef(&cbor);
	size_t size = 0;
	size_t len = 0;
	size_t offset = 0;
	byte_t *rbytes = NULL;
	for (size_t i = 0; !cbor_read_bytes_end(&cbor); i++) {
		size_t ret = cbor_read_bytes_start_len(&cbor);
		assert(ret == chunk_len[i]);
		while (!cbor_read_bytes_end(&cbor)) {
			size_t nread = cbor_read_bytes(&cbor, buf, buf_size);
			len += nread;
			if (len > size) {
				size = 2 * len;
				rbytes = realloc(rbytes, size);
			}
			memcpy(&rbytes[offset], buf, nread);
			offset += nread;
		}
	}
	assert(len == total_len);
	assert(memcmp(lbytes, rbytes, len) == 0);

	free(lbytes);
	free(rbytes);
}

int main(void)
{
	buf = iobuf_str_new(IOBUF_INIT_CAPACITY);
	cbor_init(&cbor, buf, cbor_errh_default);

	/* create several random chunks of data */
	srand(time(NULL));
	for (size_t i = 0; i < NUM_CHUNKS; i++) {
		chunk_len[i] = rand() % (1 << 12);
		chunks[i] = malloc(chunk_len[i]);
		for (size_t j = 0; j < chunk_len[i]; j++)
			chunks[i][j] = rand() % 256;
	}

	for (size_t i = 0; i < NUM_CHUNKS; i++)
		test_bytes_alloc(chunks[i], chunk_len[i]);
	test_bytes_alloc_2();
	for (size_t buf_size = 2; buf_size < 30; buf_size++) {
		test_chunked_bytes(buf_size);
		test_chunked_bytes_2(buf_size);
	}

	cbor_free(&cbor);
	iobuf_destroy(buf);
	return EXIT_SUCCESS;
}
