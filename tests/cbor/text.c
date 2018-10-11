#include "cbor.h"
#include "debug.h"
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define IOBUF_INIT_CAPACITY	400
#define STRBUF_INIT_SIZE	128

struct iobuf *buf;
struct cbor cbor;

char *test_strings[] = {
	"",
	"hello",
	"příliš žluťoučký kůň úpěl ďábelské ódy",
	"hello, world",
	"\x32\xA0\x04\x24\x24\x11\xFF\xAE",
	"hello\0world",
	"lorem ipsum dolor sit amet or whatever else you want, my dear",
	"\0",
	"\x01\x02\x03\x04",
	"",
	"ursa major",
	NULL
};

/*
 * This function will write a logical string encoded as an indefinite-length
 * text streams scattered among multiple definite-length text chunks.
 * The resulting logical string will be written to `lstr`.
 */
static void write_chunked_text(struct strbuf *lstr)
{
	cbor_write_text_start_indef(&cbor);
	for (size_t i = 0; test_strings[i] != NULL; i++) {
		strbuf_printf(lstr, "%s", test_strings[i]);
		cbor_write_text(&cbor, test_strings[i]);
	}
	cbor_write_text_end(&cbor);
	iobuf_flush(buf);
}

/*
 * Write a definite-length text stream, read it using `cbor_read_text_alloc`.
 */
static void test_text_alloc(char *str)
{
	iobuf_seek(buf, 0);
	cbor_write_text(&cbor, str);
	iobuf_flush(buf);
	iobuf_seek(buf, 0);
	char *ret;
	uint64_t len = cbor_read_text_alloc(&cbor, &ret);
	assert(ret != NULL);
	assert(len == strlen(str));
	assert(strcmp(str, ret) == 0);
	cbor_text_destroy(&cbor, ret);
}

/*
 * Write an indefinite-length text stream composed of several chunks. Then
 * use `cbor_read_text_alloc` to allocate it in and read it into memory.
 */
static void test_text_alloc_2(void)
{
	struct strbuf lstr;
	strbuf_init(&lstr, STRBUF_INIT_SIZE);
	iobuf_seek(buf, 0);
	write_chunked_text(&lstr);
	iobuf_seek(buf, 0);
	char *ret;
	uint64_t len = cbor_read_text_alloc(&cbor, &ret);
	assert(len == strlen(ret));
	assert(strcmp(ret, strbuf_get_string(&lstr)) == 0);
	strbuf_free(&lstr);
	cbor_text_destroy(&cbor, ret);
}

/*
 * Write an indefinite-length text-stream composed of several chunks. Then
 * start reading this stream using `cbor_read_text_start_indef` and consume
 * the content of the whole logical string using `cbor_read_text`.
 */
static void test_chunked_text(size_t buf_size)
{
	struct strbuf lstr;
	strbuf_init(&lstr, STRBUF_INIT_SIZE);
	iobuf_seek(buf, 0);
	write_chunked_text(&lstr);
	iobuf_seek(buf, 0);

	struct strbuf rstr;
	strbuf_init(&rstr, STRBUF_INIT_SIZE);
	char buf[buf_size];

	cbor_read_text_start_indef(&cbor);
	while (!cbor_read_text_end(&cbor)) {
		size_t nread = cbor_read_text(&cbor, buf, buf_size - 1);
		buf[nread] = '\0';
		strbuf_printf(&rstr, "%s", buf);
	}
	assert(strcmp(strbuf_get_string(&lstr), strbuf_get_string(&rstr)) == 0);

	strbuf_free(&lstr);
	strbuf_free(&rstr);
}

/*
 * Write an indefinite-length text-stream composed of several chunks. Then start
 * reading this stream using `cbor_read_text_start_indef`. Start reading each
 * chunk in the text stream explicitly using `cbor_read_text_start_len` and
 * consume it using `cbor_read_text`.
 */
static void test_chunked_text_2(size_t buf_size)
{
	struct strbuf lstr;
	strbuf_init(&lstr, 128);
	iobuf_seek(buf, 0);
	write_chunked_text(&lstr);
	iobuf_seek(buf, 0);

	struct strbuf rstr;
	strbuf_init(&rstr, STRBUF_INIT_SIZE);
	char buf[buf_size];

	cbor_read_text_start_indef(&cbor);
	for (size_t chunk_no = 0; !cbor_read_text_end(&cbor); chunk_no++) {
		size_t chunk_len = cbor_read_text_start_len(&cbor);
		assert(chunk_len == strlen(test_strings[chunk_no]));
		while (!cbor_read_text_end(&cbor)) {
			size_t nread = cbor_read_text(&cbor, buf, buf_size - 1);
			buf[nread] = '\0';
			strbuf_printf(&rstr, "%s", buf);
		}
	}
	assert(strcmp(strbuf_get_string(&lstr), strbuf_get_string(&rstr)) == 0);

	strbuf_free(&lstr);
	strbuf_free(&rstr);
}

int main(void)
{
	buf = iobuf_str_new(IOBUF_INIT_CAPACITY);
	cbor_init(&cbor, buf, cbor_errh_default);

	for (size_t buf_size = 2; buf_size < 30; buf_size++) {
		test_chunked_text(buf_size);
		test_chunked_text_2(buf_size);
	}
	for (size_t i = 0; test_strings[i] != NULL; i++)
		test_text_alloc(test_strings[i]);
	test_text_alloc_2();

	cbor_free(&cbor);
	iobuf_destroy(buf);
	return EXIT_SUCCESS;
}
