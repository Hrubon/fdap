/*
 * This module implements a high-performance CBOR encoder and decoder.
 */

#ifndef CBOR_H
#define CBOR_H

#include "except.h"
#include "iobuf.h"
#include "mempool.h"
#include "strbuf.h"
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdnoreturn.h>
#include <sys/types.h>

/*
 * Byte type (one octet, or eight bits).
 */
typedef unsigned char	byte_t;

/*
 * CBOR tag type. The `uint32_t` range is not enough to hold all CBOR tags
 * (which can be any number from 0 to $2^{64}-1$). This is a reasonable trade-off
 * between tag range and size of the `cbor_item` structure.
 */
typedef uint32_t	cbor_tag_t;

/*
 * Implementation-defined maximum value of a tag.
 */
#define CBOR_TAG_MAX	UINT32_MAX - 1

/*
 * A value which signifies the absence of a tag.
 */
#define CBOR_TAG_NONE	UINT32_MAX

/******************************** CBOR stream ********************************/

/*
 * Functions for manipulation with a CBOR stream handle.
 */

struct cbor;

/*
 * Prototype of an error-handler. When called, the error handler is required
 * to guarantee that no further operations are called on `c`, otherwise the
 * behavior is undefined.
 *
 * This allows you to build a simple exception-like handling mechanism using the
 * `longjmp`/`setjmp` combo. See `tests/cbor/error.c` for an example.
 */
typedef void (cbor_errh_t)(struct cbor *c);

/*
 * Default error handler implementation. Logs the error using the `LOG`
 * macro and then calls `exit` with `EXIT_FAILURE` as the return code,
 * thereby terminating the calling process.
 */
void cbor_errh_default(struct cbor *c);

/*
 * When called, this error handler will use the `throw` macro of `except.h`
 * to perform a `longjmp` to a location set by a previous `setjmp`, which
 * is usually set by the `try` macro of the same header file. This approach
 * allows us to emulate exceptions nicely.
 */
void cbor_errh_throw(struct cbor *c);

/*
 * CBOR stream representation. This is the handle passed to almost all functions
 * of this module. It encapsulates the processing context of the encoding/decoding
 * process.
 */
struct cbor
{
	struct iobuf *buf;	/* the underlying I/O buffer */
	cbor_errh_t *errh;	/* error-handling function */
	struct strbuf errmsg;	/* error message buffer */
	struct scope *scopes;	/* array of open scopes */
};

/*
 * Initialize a CBOR stream pointed to by `c`. All I/O operations will
 * act upon the underlying `buf` buffer. If an error occurs, `errh` will be
 * called to handle it (see `cbor_errh_t`).
 */
void cbor_init(struct cbor *c, struct iobuf *buf, cbor_errh_t *errh);

/*
 * Free all resources held by `c`.
 */
void cbor_free(struct cbor *c);

/*
 * Get a textual description of the last error which occurred. The returned
 * memory is owned by `c`, don't pass it to `free`. The returned string is
 * only valid until any operation other than `cbor_strerror` is called on `c`.
 */
char *cbor_strerror(struct cbor *c);

/******************************** Generic items ********************************/

/*
 * Generic item-based encoding and decoding API.
 */

/*
 * CBOR item flags.
 */
enum cbor_flag
{
	CBORF_ETEXT = 1,	/* text is embedded in the item */
	CBORF_ETAG = 2,		/* tag is embedded in the item */
};

/*
 * Logical type of a CBOR item. This is not the major type of the item, though
 * there's a 1--1 correspondence in many cases.
 *
 * TODO Rename `CBOR_TYPE_*` to `CBOR_*`.
 */
enum cbor_type
{
	CBOR_TYPE_UINT,
	CBOR_TYPE_INT,
	CBOR_TYPE_BYTES,
	CBOR_TYPE_TEXT,
	CBOR_TYPE_ARRAY,
	CBOR_TYPE_MAP,
	CBOR_TYPE_TAG,
	CBOR_TYPE_SVAL,
};

/*
 * CBOR simple value. A "value with no content" the meaning of which is given
 * by the RFC. (Major type 7.)
 */
enum cbor_sval
{
	CBOR_SVAL_FALSE = 20,
	CBOR_SVAL_TRUE,
	CBOR_SVAL_NULL,
	CBOR_SVAL_UNDEF,
};

const char *cbor_type_to_string(enum cbor_type type);

/*
 * In-memory representation of a generic CBOR item. The meaning of the `u16`
 * field is user-defined, this module does not touch it.
 */
struct cbor_item
{
	byte_t type;	/* type of this item */
	byte_t flags;	/* various flags */
	uint16_t u16;	/* user-defined field */
	union
	{
		char etext[12];	/* embedded text */
		struct
		{
			uint32_t u32;	/* size information or a tag */
			union
			{
				uint64_t u64;			/* CBOR_UINT */
				int64_t i64;			/* CBOR_INT */
				char *text;			/* CBOR_TEXT */
				byte_t *bytes;			/* CBOR_BYTES */
				enum cbor_sval sval;		/* CBOR_SVAL */
				struct cbor_item *items;	/* CBOR_ARRAY */
				struct cbor_pair *pairs;	/* CBOR_MAP */
				struct cbor_item *tagged;	/* CBOR_TYPE_TAG */
			};
		};
	};
};

/*
 * A key-value pair.
 */
struct cbor_pair
{
	struct cbor_item key;	/* key item */
	struct cbor_item value;	/* value item */
};

void cbor_item_init(struct cbor_item *item);
void cbor_item_set_int(struct cbor_item *item, int64_t i64);
char *cbor_item_set_text(struct cbor_item *item, char *text);
char *cbor_item_set_escaped_text(struct cbor_item *item, char *text);
char *cbor_item_set_text_pool(struct cbor_item *item, char *text, struct mempool *pool);
char *cbor_item_set_escaped_text_pool(struct cbor_item *item, char *text, struct mempool *pool);
byte_t *cbor_item_set_bytes(struct cbor_item *item, byte_t *bytes, size_t nbytes);
void cbor_item_set_array(struct cbor_item *item, struct cbor_item *items, size_t nitems);
void cbor_item_set_map(struct cbor_item *item, struct cbor_pair *pairs, size_t nitems);
void cbor_item_set_tagged(struct cbor_item *item, cbor_tag_t tag, struct cbor_item *tagged);
void cbor_item_set_sval(struct cbor_item *item, uint8_t sval);
void cbor_item_free(struct cbor_item *item);

void cbor_item_set_array_start(struct cbor_item *item);
struct cbor_item *cbor_item_new_array_item(struct cbor_item *item);
void cbor_item_set_array_end(struct cbor_item *item);

void cbor_item_set_map_start(struct cbor_item *item);
struct cbor_pair *cbor_item_new_map_item(struct cbor_item *item);
void cbor_item_set_map_end(struct cbor_item *item);

void cbor_read_item(struct cbor *c, struct cbor_item *item);
void cbor_write_item(struct cbor *c, struct cbor_item *item);

size_t cbor_text_escape(char *text, struct strbuf *buf);
char *cbor_text_unescape(char *text);
char *cbor_item_get_text(struct cbor_item *item);
char *cbor_item_get_text_escaped(struct cbor_item *item);

void cbor_item_dump(struct cbor_item *item, struct strbuf *str);
int cbor_item_cmp(struct cbor_item *a, struct cbor_item *b);

/*
 * If `item` is not tagged, return false. Otherwise, remove the tag from
 * `item`, store it to `tag`, discard the tag from `item` and return `true`.
 *
 * NOTE This operation is destructive, as it overrides `item` with the tagged
 *      item. Unless this is what you want, get a copy of the original item
 *      first. Cleaner API would be possible if it wasn't for tag embedding.
 *      But it wasn't meant to be.
 */
bool cbor_item_strip_tag(struct cbor_item *item, cbor_tag_t *tag);

/******************************** Integers ********************************/

/*
 * Encoding and decoding of unsigned and negative integers (major types 0 and 1).
 */

/*
 * Read an 8-bit unsigned integer from `c`.
 */
uint8_t cbor_read_u8(struct cbor *c);

/*
 * Read a 16-bit unsigned integer from `c`.
 */
uint16_t cbor_read_u16(struct cbor *c);

/*
 * Read a 32-bit unsigned integer from `c`.
 */
uint32_t cbor_read_u32(struct cbor *c);

/*
 * Read a 64-bit unsigned integer from `c`.
 */
uint64_t cbor_read_u64(struct cbor *c);

/*
 * Read an 8-bit signed integer from `c`.
 */
int8_t cbor_read_i8(struct cbor *c);

/*
 * Read an 16-bit signed integer from `c`.
 */
int16_t cbor_read_i16(struct cbor *c);

/*
 * Read an 32-bit signed integer from `c`.
 */
int32_t cbor_read_i32(struct cbor *c);

/*
 * Read an 64-bit signed integer from `c`.
 */
int64_t cbor_read_i64(struct cbor *c);

/*
 * Write an 8-bit unsigned integer to `c`.
 */
void cbor_write_u8(struct cbor *c, uint8_t u8);

/*
 * Write a 16-bit unsigned integer to `c`.
 */
void cbor_write_u16(struct cbor *c, uint16_t u16);

/*
 * Write a 32-bit unsigned integer to `c`.
 */
void cbor_write_u32(struct cbor *c, uint32_t u32);

/*
 * Write a 64-bit unsigned integer to `c`.
 */
void cbor_write_u64(struct cbor *c, uint64_t u64);

/*
 * Write an 8-bit signed integer to `c`.
 */
void cbor_write_i8(struct cbor *c, int8_t i8);

/*
 * Write an 16-bit signed integer to `c`.
 */
void cbor_write_i16(struct cbor *c, int16_t i16);

/*
 * Write an 32-bit signed integer to `c`.
 */
void cbor_write_i32(struct cbor *c, int32_t i32);

/*
 * Write a 64-bit signed integer to `c`.
 */
void cbor_write_i64(struct cbor *c, int64_t i64);

/******************************** Text streams ********************************/

/*
 * Encoding and decoding of text streams (major type 2).
 */

/*
 * Read up to `nbytes` bytes from a logical text-stream into the user-provided
 * buffer `dst`. Return the number of bytes actually written into `dst`. If 0
 * is returned, end of the text stream was reached.
 *
 * One of the `cbor_read_text_start_*` functions must be called first to
 * initialize the reading process. `cbor_read_text` then reads from the
 * logical rather than physical text stream, i.e. it does not matter whether
 * the stream was encoded as a definite- or indefinite-length stream, how many
 * chunks there are, etc.
 *
 * Please see `tests/cbor/text.c` for advanced usage examples.
 */
size_t cbor_read_text(struct cbor *c, char *dst, size_t nbytes);

/*
 * Start reading a text stream (definite- or indefinite-length).
 */
void cbor_read_text_start(struct cbor *c);

/*
 * Start reading a definite-length text stream. The length of the stream
 * is returned.
 */
uint64_t cbor_read_text_start_len(struct cbor *c);

/*
 * Start reading an indefinite-length text stream.
 */
void cbor_read_text_start_indef(struct cbor *c);

/*
 * Stop reading a text stream. Call to this function will succeed (returning
 * `true`) only if the whole stream was read; otherwise, it has no side-effects
 * besides wasting time.
 */
bool cbor_read_text_end(struct cbor *c);

/*
 * Read a definite- or indefinite-length text stream and save its contents into
 * a newly allocated string `str` in memory. Total length of the string
 * in bytes is returned. The string is `NUL`-terminated.
 *
 * When no longer needed, `str` must be disposed by a call to `cbor_text_destroy`.
 * Alternatively, all strings which were not freed by `cbor_text_destroy`
 * will be freed once `cbor_free` is called on `c`.
 */
uint64_t cbor_read_text_alloc(struct cbor *c, char **str);

/*
 * Destroy the string `str` allocated by a call to `cbor_read_text_alloc`.
 */
void cbor_text_destroy(struct cbor *c, char *str);

/*
 * Write the string `str` to `c` as a definite-length text stream.
 */
void cbor_write_text(struct cbor *c, char *str);

/*
 * Start writing an indefinite-length text stream to `c`. The individual chunks are
 * to be written using `cbor_write_text`.
 */
void cbor_write_text_start_indef(struct cbor *c);

/*
 * Stop writing an indefinite-length text stream.
 */
void cbor_write_text_end(struct cbor *c);

/******************************** Byte streams ********************************/

/*
 * Encoding and decoding of byte streams (major type 3).
 */

/*
 * Read up to `nbytes` bytes from a logical byte-stream into the user-provided
 * buffer `dst`. Return the number of bytes actually written into `dst`. If 0
 * is returned, end of the byte stream was reached.
 *
 * One of the `cbor_read_bytes_start_*` functions must be called first to
 * initialize the reading process. `cbor_read_bytes` then reads from the
 * logical rather than physical byte stream, i.e. it does not matter whether
 * the stream was encoded as a definite- or indefinite-length stream, how many
 * chunks there are, etc.
 *
 * Please see `tests/cbor/bytes.c` for advanced usage examples.
 */
size_t cbor_read_bytes(struct cbor *c, byte_t *dst, size_t nbytes);

/*
 * Start reading a byte stream (definite- or indefinite-length).
 */
void cbor_read_bytes_start(struct cbor *c);

/*
 * Start reading a definite-length byte stream. The length of the stream
 * is returned.
 */
uint64_t cbor_read_bytes_start_len(struct cbor *c);

/*
 * Start reading an indefinite-length byte stream.
 */
void cbor_read_bytes_start_indef(struct cbor *c);

/*
 * Stop reading a byte stream. Call to this function will succeed (returning
 * `true`) only if the whole stream was read; otherwise, it has no side-effects
 * besides wasting time.
 */
bool cbor_read_bytes_end(struct cbor *c);

/*
 * Read a definite- or indefinite-length byte stream and save its contents into
 * a newly allocated buffer `buf` in memory. Total length of the stream
 * in bytes is returned.
 *
 * When no longer needed, `buf` must be disposed by a call to `cbor_bytes_destroy`.
 * Alternatively, all byte streams which were not freed by `cbor_bytes_destroy`
 * will be freed once `cbor_free` is called on `c`.
 */
uint64_t cbor_read_bytes_alloc(struct cbor *c, byte_t **buf);

/*
 * Destroy the buffer `buf` allocated by a call to `cbor_read_bytes_alloc`.
 */
void cbor_bytes_destroy(struct cbor *c, byte_t *buf);

/*
 * Write `nbytes` bytes of the byte stream contained in buffer `buf` to `c`.
 * Encode it as a definite-length byte stream.
 */
void cbor_write_bytes(struct cbor *c, byte_t *buf, size_t nbytes);

/*
 * Start writing an indefinite-length byte-stream to `c`. The individual
 * chunks are to be written using `cbor_write_bytes`.
 */
void cbor_write_bytes_start_indef(struct cbor *c);

/*
 * Stop writing an indefinite-length byte-stream.
 */
void cbor_write_bytes_end(struct cbor *c);

/******************************** Arrays ********************************/

/*
 * Encoding and decoding of arrays (major type 4).
 */

/*
 * Start reading an indefinite- or definite-length array.
 */
void cbor_read_array_start(struct cbor *c);

/*
 * Start reading a definite-length array, return the number of items it contains.
 */
uint64_t cbor_read_array_start_size(struct cbor *c);

/*
 * Start reading an indefinite-length array.
 */
void cbor_read_array_start_indef(struct cbor *c);

/*
 * Stop reading an array. This function only succeeds if all items in the
 * array have been read, otherwise it is a no-op.
 */
bool cbor_read_array_end(struct cbor *c);

/*
 * Start writing an array which will contain `len` items.
 */
void cbor_write_array_start_size(struct cbor *c, uint64_t len);

/*
 * Start writing an indefinite-length array.
 */
void cbor_write_array_start_indef(struct cbor *c);

/*
 * Stop writing an array.
 */
void cbor_write_array_end(struct cbor *c);

/******************************** Maps ********************************/

/*
 * Encoding and decoding of maps (major type 5).
 */

/*
 * Start reading an indefinite- or definite-length map;
 */
void cbor_read_map_start(struct cbor *c);

/*
 * Start reading a definite-length map, return the number of pairs it contains.
 */
uint64_t cbor_read_map_start_size(struct cbor *c);

/*
 * Start reading an indefinite-length map.
 */
void cbor_read_map_start_indef(struct cbor *c);

/*
 * Stop reading a map. This function only succeeds if all items in the map
 * have been read, otherwise it is a no-op.
 */
bool cbor_read_map_end(struct cbor *c);

/*
 * Start writing a map which will contain `size` pairs.
 */
void cbor_write_map_start_size(struct cbor *c, uint64_t size);

/*
 * Start writing an indefinite-length map.
 */
void cbor_write_map_start_indef(struct cbor *c);

/*
 * Stop writing a map.
 */
void cbor_write_map_end(struct cbor *c);

/******************************** Tags ********************************/

/*
 * Encoding and decoding of semantic tags (major type 6).
 */

/*
 * Read a tag.
 */
cbor_tag_t cbor_read_tag(struct cbor *c);

/*
 * Write a tag.
 */
void cbor_write_tag(struct cbor *c, cbor_tag_t tag);

/******************************** Simple values ********************************/

/*
 * Read a simple value from `c`.
 */
uint8_t cbor_read_sval(struct cbor *c);

/*
 * Write the simple value `sval` to `c`.
 */
void cbor_write_sval(struct cbor *c, uint8_t sval);

/*
 * Write the bool `b` to `c`. Write either `CBOR_SVAL_TRUE` or `CBOR_SVAL_FALSE`.
 */
void cbor_write_bool(struct cbor *c, bool b);

/*
 * Read a bool from `c`. Assumes the item is either `CBOR_SVAL_TRUE`
 * or `CBOR_SVAL_FALSE`, otherwise it's an error.
 */
bool cbor_read_bool(struct cbor *c);

#endif
