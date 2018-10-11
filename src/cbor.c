#include "array.h"
#include "cbor.h"
#include "common.h"
#include "log.h"
#include "memory.h"
#include "mempool.h"
#include "strbuf.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define MAJOR(b)		(((b) & 0xE0) >> 5)
#define MINOR(b)		((b) & 0x1F)

#define MINOR_1B		24
#define MINOR_2B		25
#define MINOR_4B		26
#define MINOR_8B		27
#define MINOR_FLOAT_HALF	25
#define MINOR_FLOAT_SINGLE	26
#define MINOR_FLOAT_DOUBLE	27
#define MINOR_INDEF		31

#define INDEF(hdr)		(MINOR(hdr) == MINOR_INDEF)
#define BREAK			0xFF
#define DIRECT_VALUE_MAX	23
#define NEGINT_DECODE_MAX	(-(INT64_MIN + 1))

#define ARRAY_INIT_SIZE	4
#define MAP_INIT_SIZE	3

#define STRBUF_INIT_SIZE	128
#define INIT_SCOPES_COUNT	8
#define STREAM_INIT_SIZE	16
#define STR_MAX_LEN		2048

#define TRIM_STREAMS		1
#define EMBED_SHORT_TEXT	1

/*
 * Major type of a CBOR item.
 */
enum major
{
	MAJOR_UINT,
	MAJOR_NEGINT,
	MAJOR_BYTES,
	MAJOR_TEXT,
	MAJOR_ARRAY,
	MAJOR_MAP,
	MAJOR_TAG,
	MAJOR_7,
	MAJOR_NOTSET,
};

/*
 * Return a human-readable name for major type `major`.
 */
static const char *strmajor(byte_t major)
{
	switch (major) {
	case MAJOR_UINT:	return "uint";
	case MAJOR_NEGINT:	return "negint";
	case MAJOR_ARRAY:	return "array";
	case MAJOR_MAP:		return "map";
	case MAJOR_TEXT:	return "text";
	case MAJOR_BYTES:	return "bytes";
	case MAJOR_TAG:		return "tag";
	case MAJOR_7:		return "sval";
	default:		assert(0);
	}
}

/*
 * Return a human-readable name for simple value `sval`.
 */
static char *dump_sval(enum cbor_sval sval)
{
	switch (sval) {
	case CBOR_SVAL_FALSE:	return "false";
	case CBOR_SVAL_TRUE:	return "true";
	case CBOR_SVAL_NULL:	return "null";
	case CBOR_SVAL_UNDEF:	return "undef";
	default:		assert(0);
	}
}

/*
 * Invoke the error handler and set a formatted error message. The error
 * message can later be retrieved by a call to `cbor_strerror`.
 *
 * Any further operations on `c` with the exception of `cbor_strerror`
 * and `cbor_free` are undefined and most likely fatal.
 */
noreturn static void err(struct cbor *c, char *msg, ...)
{
	va_list args;
	va_start(args, msg);
	strbuf_vprintf_at(&c->errmsg, 0, msg, args);
	va_end(args);
	c->errh(c);
	LOG(LOG_ERR, "CBOR error handler did not abort execution, exiting!");
	exit(EXIT_FAILURE);
}

/*
 * Certain CBOR items, namely byte and text streams, arrays and maps are usually
 * not encoded or decoded using a single call to the decoder. For example, to
 * decode a byte stream, one has to start by calling one of the
 * `cbor_bytes_read_start_*` functions, followed by several calls to
 * `cbor_bytes_read` calls, followed by a call to `cbor_bytes_read_end`.
 *
 * To keep track of the state of the encoding/decoding process, the `scope`
 * structure is introduced. This allows us to spot common errors, such as reading
 * too little from a byte stream or writing more items to an array than
 * its declared size is, etc.
 *
 * The `u64` and `counter` members are item-type-specific and are used for this
 * accounting. For byte and text streams, for example, these amount to the
 * number of bytes in the stream and the number of bytes read/written so far,
 * respectively.
 *
 * The `auto_end` flag is true precisely when then scope was not started by
 * the user (by calling some `cbor_*_start_*` function) but rather by internal
 * code, so internal code should call the appropriate function to end the
 * context, too.
 *
 * TODO Consider renaming `auto_end` to something more descriptive.
 */
struct scope
{
	byte_t hdr;		/* header of the item which started the scope */
	bool auto_end;		/* should this scope be ended automatically? */
	uint64_t u64;		/* quantity (number of items, bytes, ...) */
	uint64_t counter;	/* counter (read items, written bytes, ...) */
};

/*
 * Return the currently open scope. If the scope stack is empty, it is an error.
 */
static struct scope *scope(struct cbor *c)
{
	return &ARRAY_LAST(c->scopes);
}

/*
 * Returns true if there's no scope open.
 *
 * There's always one scope: the bottom-most one, which is opened by
 * `cbor_init`. This is an artificial scope with `hdr` set to `BREAK`
 * (because no other scope can have such `hdr` value). It was added so that
 * when we increment the number of items read/written in current scope in
 * `read_hdr` and `write_hdr`, we don't have to worry about whether the scope
 * stack is empty or not. This makes the process faster, too, because branching
 * on the hot path is reduced.
 */
static bool no_scope(struct cbor *c)
{
	return scope(c)->hdr == BREAK;
}

/*
 * Start a new scope for an item with header byte `hdr` and quantity `u64`.
 * If the item uses indefinite-length encoding, set `u64` to 0.
 */
static void start_scope(struct cbor *c, byte_t hdr, uint64_t u64)
{
	struct scope *s = ARRAY_RESERVE(c->scopes);
	s->hdr = hdr;
	s->u64 = u64;
	s->counter = 0;
	s->auto_end = false;
}

/*
 * End current scope. If the scope stack is empty, it is an error.
 */
static void end_scope(struct cbor *c)
{
	if (no_scope(c))
		err(c, "cannot end scope, there's no scope open");
	(void) ARRAY_POP(c->scopes);
}

/*
 * Return the number of remaining items in scope `s`.
 */
static uint64_t scope_remains(struct scope *s)
{
	assert(!INDEF(s->hdr));
	assert(s->u64 >= s->counter);
	return s->u64 - s->counter;
}

/*
 * Ensure that current scope has major type `major` and return it.
 */
static struct scope *scope_check(struct cbor *c, byte_t major)
{
	struct scope *s = scope(c);
	if (s->hdr == BREAK || MAJOR(s->hdr) != major)
		err(c, "operation requires %s scope", strmajor(major));
	return s;
}

static bool can_embed_tagged(struct cbor_item *item)
{
	return !(item->flags & CBORF_ETEXT ||
		item->type == CBOR_TYPE_BYTES ||
		item->type == CBOR_TYPE_ARRAY ||
		item->type == CBOR_TYPE_MAP);
}

void cbor_item_init(struct cbor_item *item)
{
	item->flags = 0;
	item->type = MAJOR_NOTSET;
}

void cbor_item_set_int(struct cbor_item *item, int64_t i64)
{
	cbor_item_init(item);
	if (i64 < 0) {
		item->type = MAJOR_NEGINT;
		item->i64 = i64;
	} else {
		item->type = MAJOR_UINT;
		item->u64 = (uint64_t)i64;
	}
}

char *cbor_item_set_text(struct cbor_item *item, char *text)
{
	cbor_item_init(item);
	item->type = MAJOR_TEXT;
	size_t sz = sizeof(item->etext);
	if (EMBED_SHORT_TEXT && strlen(text) < sz) {
		item->flags = CBORF_ETEXT;
		strncpy(item->etext, text, sz);
		item->etext[sz - 1] = '\0';
		return item->etext;
	} else {
		item->text = strndup(text, STR_MAX_LEN);
		return item->text;
	}
}

char *cbor_item_set_escaped_text(struct cbor_item *item, char *text)
{
	char *str = cbor_item_set_text(item, text);
	return cbor_text_unescape(str);
}

char *cbor_item_set_text_pool(struct cbor_item *item, char *text, struct mempool *pool)
{
	cbor_item_init(item);
	item->type = MAJOR_TEXT;
	item->text = mempool_strdup(pool, text);
	return item->text;
}

char *cbor_item_set_escaped_text_pool(struct cbor_item *item, char *text, struct mempool *pool)
{
	char *str = cbor_item_set_text_pool(item, text, pool);
	return cbor_text_unescape(str);
}

byte_t *cbor_item_set_bytes(struct cbor_item *item, byte_t *bytes, size_t nbytes)
{
	cbor_item_init(item);
	item->type = MAJOR_BYTES;
	item->bytes = fdap_malloc(nbytes);
	return memcpy(item->bytes, bytes, nbytes);
}

void cbor_item_set_array(struct cbor_item *item, struct cbor_item *items, size_t nitems)
{
	cbor_item_init(item);
	item->type = MAJOR_ARRAY;
	item->u32 = nitems;
	item->items = array_new(nitems, sizeof(*items));
	for (size_t i = 0; i < nitems; i++) {
		ARRAY_PUSH(item->items, items[i]);
	}
}

void cbor_item_set_array_start(struct cbor_item *item)
{
	cbor_item_init(item);
	item->type = MAJOR_ARRAY;
	item->items = array_new(ARRAY_INIT_SIZE, sizeof(*item->items));
	item->u32 = 0;
}

struct cbor_item *cbor_item_new_array_item(struct cbor_item *item)
{
	struct cbor_item *it = ARRAY_RESERVE(item->items);
	cbor_item_init(it);
	item->u32++;
	return it;
}

void cbor_item_set_array_end(struct cbor_item *item)
{
	item->u32 = ARRAY_SIZE(item->items);
}

void cbor_item_set_map(struct cbor_item *item, struct cbor_pair *pairs, size_t npairs)
{
	cbor_item_init(item);
	item->type = MAJOR_MAP;
	item->u32 = npairs;
	item->pairs = array_new(npairs, sizeof(*pairs));
	for (size_t i = 0; i < npairs; i++) {
		ARRAY_PUSH(item->pairs, pairs[i]);
	}
}

void cbor_item_set_map_start(struct cbor_item *item)
{
	cbor_item_init(item);
	item->type = MAJOR_MAP;
	item->pairs = array_new(MAP_INIT_SIZE, sizeof(*item->pairs));
	item->u32 = 0;
}

struct cbor_pair *cbor_item_new_map_item(struct cbor_item *item)
{
	struct cbor_pair *pair = ARRAY_RESERVE(item->pairs);
	cbor_item_init(&pair->key);
	cbor_item_init(&pair->value);
	item->u32++;
	return pair;
}

void cbor_item_set_map_end(struct cbor_item *item)
{
	item->u32 = ARRAY_SIZE(item->pairs);
}

void cbor_item_set_tagged(struct cbor_item *item, cbor_tag_t tag, struct cbor_item *tagged)
{
	cbor_item_init(item);
	if (can_embed_tagged(tagged)) {
		*item = *tagged;
		item->flags = CBORF_ETAG;
	} else {
		item->tagged = fdap_malloc(sizeof(*item->tagged));
		*item->tagged = *tagged;
	}
	item->u32 = tag;
}

void cbor_item_set_sval(struct cbor_item *item, uint8_t sval)
{
	cbor_item_init(item);
	item->type = CBOR_TYPE_SVAL;
	item->sval = sval;
}

/*
 * Frees all resources allocated with `cbor_item` `item`.
 */
void cbor_item_free(struct cbor_item *item)
{
	switch (item->type) {
		case MAJOR_UINT:
		case MAJOR_NEGINT:
		case MAJOR_7:
		case MAJOR_NOTSET:
			break;
		case MAJOR_TEXT:
			if (!(item->flags & CBORF_ETEXT))
				free(item->text);
			break;
		case MAJOR_BYTES:
			free(item->bytes);
			break;
		case MAJOR_ARRAY:
			for (size_t i = 0; i < item->u32; i++) {
				cbor_item_free(&item->items[i]);
			}
			array_destroy(item->items);
			break;
		case MAJOR_MAP:
			for (size_t i = 0; i < item->u32; i++) {
				cbor_item_free(&item->pairs[i].key);
				cbor_item_free(&item->pairs[i].value);
			}
			array_destroy(item->pairs);
			break;
		case MAJOR_TAG:
			if (!(item->flags & CBORF_ETAG)) {
				cbor_item_free(item->tagged);
				free(item->tagged);
			}
			break;
		default:
			assert(0);
	}
}

size_t cbor_text_escape(char *text, struct strbuf *buf)
{
	strbuf_putc(buf, '\'');
	size_t nslash = 0;
	size_t nwritten = 0;
	for (size_t i = 0; ; i++) {
		if (text[i] == '\\')
			nslash++;
		else {
			if (text[i] == '\'') {
				if (nslash % 2 == 0) {
					strbuf_putc(buf, '\\');
					nwritten++;
				}
			} else {
				if (nslash % 2 != 0) {
					strbuf_putc(buf, '\\');
					nwritten++;
				}
			}
			nslash = 0;
		}
		if (text[i] == '\0')
			break;
		strbuf_putc(buf, text[i]);
		nwritten++;
	}
	strbuf_putc(buf, '\'');
	return nwritten + 2;
}

char *cbor_text_unescape(char *text)
{
	size_t j = 0;
	for (size_t i = 1; ; i++) {
		if (text[i] == '\\' && (text[i + 1] == '\'' || text[i + 1] == '\\')) { 
			text[j] = text[i + 1];
			i++;
		}
		else if (text[i + 1] == '\0') {
			text[j] = '\0';
			break;
		}
		else
			text[j] = text[i];
		j++;
	}
	return text;
}



void cbor_init(struct cbor *c, struct iobuf *buf, cbor_errh_t *errh)
{
	c->buf = buf;
	c->errh = errh;
	strbuf_init(&c->errmsg, STRBUF_INIT_SIZE);
	c->scopes = array_new(INIT_SCOPES_COUNT, sizeof(*c->scopes));
	start_scope(c, BREAK, 0); /* artificial item so that the array is never empty */
}

void cbor_free(struct cbor *c)
{
	iobuf_flush(c->buf);
	strbuf_free(&c->errmsg);
	array_destroy(c->scopes);
}

char *cbor_strerror(struct cbor *c)
{
	return strbuf_get_string(&c->errmsg);
}

void cbor_errh_default(struct cbor *c)
{
	(void) c;
	LOGF(LOG_ERR, "CBOR error: %s", cbor_strerror(c));
	exit(EXIT_FAILURE);
}

void cbor_errh_throw(struct cbor *c)
{
	(void) c;
	LOGF(LOG_ERR, "CBOR error: %s", cbor_strerror(c));
	throw;
}

/*
 * Read `nbytes` bytes from the underlying buffer.
 *
 * If end-of-file is reached and `nbytes > 0`, it is an error. If an error
 * occurs during the read operation on the buffer, `err` will be called.
 */
static void read_cbor(struct cbor *c, void *buf, size_t nbytes)
{
	ssize_t ret = iobuf_read(c->buf, buf, nbytes);
	if (ret < 0)
		err(c, "I/O error");
	if ((size_t)ret < nbytes)
		err(c, "unexpected EOF");
}

/*
 * This function has the same semantics as `read`, but only reads
 * a single byte which it returns.
 */
static inline byte_t read_byte(struct cbor *c)
{
	int ret = iobuf_getc(c->buf);
	if (ret < 0)
		err(c, "I/O error or unexpected EOF");
	return (byte_t)ret;
}

/*
 * Read the header byte and increase current scope counter.
 */
static byte_t read_hdr(struct cbor *c)
{
	scope(c)->counter++;
	return read_byte(c);
}

/*
 * Return the next byte in the CBOR stream without consuming it.
 */
static inline byte_t peek(struct cbor *c)
{
	int ret = iobuf_peek(c->buf);
	if (ret < 0)
		err(c, "I/O error");
	return (byte_t)ret;
}

/*
 * Is the next item a break code?
 */
static inline bool break_follows(struct cbor *c)
{
	return peek(c) == BREAK;
}

/*
 * Check that the given header byte `hdr` has major type set to `major`. If
 * `indef` is either a positive number or zero, check that `hdr` marks an item
 * which is indefinite- or definite-length, respectively. (If `indef` is
 * negative, don't check for definiteness.)
 */
static void check_type(struct cbor *c, byte_t hdr, byte_t major, int indef)
{
	byte_t h_major = MAJOR(hdr);
	if (h_major != major)
		err(c, "%s expected, got %s", strmajor(major), strmajor(h_major));
	if (indef >= 0 && INDEF(hdr) != indef)
		err(c, "indefinite-length encoding was %sexpected", indef ? "" : "un");
}

/*
 * Read next item's header and return it. Also, decode the related quantity
 * and store it into `*u64`.
 *
 * If the item uses indefinite-length encoding, `*u64` will be set to a 0.
 */
static byte_t read_hdr_u64(struct cbor *c, uint64_t *u64)
{
	byte_t hdr = read_hdr(c);
	byte_t minor = MINOR(hdr);

	if (minor <= DIRECT_VALUE_MAX) {
		*u64 = minor;
	} else if (minor == MINOR_INDEF) {
		*u64 = 0;
	} else if (minor > MINOR_8B) {
		err(c, "invalid minor bits (0x%02X, %u)", minor, minor);
	} else {
		uint64_t u64be = 0;
		byte_t *u64be_ptr = (byte_t *)&u64be;
		size_t enc_len = 1 << (minor - MINOR_1B);
		read_cbor(c, &u64be_ptr[sizeof(uint64_t) - enc_len], enc_len);
		*u64 = be64toh(u64be);
	}
	return hdr;
}

/*
 * Read an unsigned integer. Require that it is less than or equal to `max`,
 * otherwise it's an error.
 */
static uint64_t read_uint(struct cbor *c, uint64_t max)
{
	uint64_t u64;
	check_type(c, read_hdr_u64(c, &u64), MAJOR_UINT, false);
	if (u64 > max)
		err(c, "uint between 0 and %lu was expected, got %lu", max, u64);
	return u64;
}

/*
 * Read an integer. This can be either an unsigned int (major type 0)
 * or a negative int (major type 1) in the CBOR stream. In any case, require
 * that the resulting integer lies between `min` and `max` inclusive, otherwise
 * it's an error.
 */
static int64_t read_int(struct cbor *c, int64_t min, int64_t max)
{
	uint64_t u64;
	byte_t major = MAJOR(read_hdr_u64(c, &u64));
	if (major > MAJOR_NEGINT)
		err(c, "uint or negative int expected, got %s", strmajor(major));
	int64_t i64;
	if (major) { /* negative int */
		if (u64 > NEGINT_DECODE_MAX) /* would overflow */
			err(c, "cannot decode int < -%lu", NEGINT_DECODE_MAX);
		i64 = -u64 - 1;
	} else {
		if (u64 > INT64_MAX)
			err(c, "expected int <= %li, got %lu", max, u64);
		i64 = (int64_t)u64; /* u64 <= INT64_MAX */
	}
	if (i64 < min || i64 > max)
		err(c, "int between %li and %li was expected, got %li", min, max, i64);
	return i64;
}

uint8_t cbor_read_u8(struct cbor *c)
{
	return (uint8_t)read_uint(c, UINT8_MAX);
}

uint16_t cbor_read_u16(struct cbor *c)
{
	return (uint16_t)read_uint(c, UINT16_MAX);
}

uint32_t cbor_read_u32(struct cbor *c)
{
	return (uint32_t)read_uint(c, UINT32_MAX);
}

uint64_t cbor_read_u64(struct cbor *c)
{
	return (uint64_t)read_uint(c, UINT64_MAX);
}

int8_t cbor_read_i8(struct cbor *c)
{
	return (int8_t)read_int(c, INT8_MIN, INT8_MAX);
}

int16_t cbor_read_i16(struct cbor *c)
{
	return (int16_t)read_int(c, INT16_MIN, INT16_MAX);
}

int32_t cbor_read_i32(struct cbor *c)
{
	return (int32_t)read_int(c, INT32_MIN, INT32_MAX);
}

int64_t cbor_read_i64(struct cbor *c)
{
	return (int64_t)read_int(c, INT64_MIN, INT64_MAX);
}

static uint64_t read_scope_start(struct cbor *c, byte_t major, int indef)
{
	uint64_t u64;
	byte_t hdr = read_hdr_u64(c, &u64);
	check_type(c, hdr, major, indef);
	if (major != MAJOR_MAP)
		start_scope(c, hdr, u64);
	else
		start_scope(c, hdr, 2 * u64);
	return u64;
}

static bool read_scope_end(struct cbor *c, byte_t major)
{
	struct scope *s = scope_check(c, major);
	if (INDEF(s->hdr)) {
		if (!break_follows(c))
			return false;
		read_byte(c); /* read the `BREAK` code */
	} else if (scope_remains(s)) {
		return false;
	}
	end_scope(c);
	return true;
}

/*
 * Read either a text or a byte stream (depending on `major`). This function
 * reads the logical stream: if an indefinite-length stream is being read,
 * it correctly decodes the intervening chunks.
 */
static size_t read_stream(struct cbor *c, byte_t major, void *dst, size_t nbytes)
{
	for (;;) {
		struct scope *s = scope_check(c, major);
		if (INDEF(s->hdr)) {
			if (break_follows(c))
				return 0;
			read_scope_start(c, major, false); /* next chunk */
			s = scope(c);
			s->auto_end = true;
		}
		size_t to_read = MIN(nbytes, scope_remains(s));
		read_cbor(c, dst, to_read);
		s->counter += to_read; 
		if (!scope_remains(s) && s->auto_end)
			end_scope(c);
		return to_read;
	}
}

/*
 * An allocating wrapper for the stream reading functions. Reads a whole
 * logical byte or text stream (depending on `major`) and stores it in `*buf`.
 * The total length of the decoded stream is returned. (Excluding the trailing
 * `NUL` byte in case of text streams.)
 *
 * This function will `NUL`-terminate the stream, even if it's a byte stream.
 * This is necessary for strings and does not do any harm for byte strings.
 * It can however hide some plus one errors in the code that reads the
 * stream from sanitizers. TODO Is this a problem?
 */
static uint64_t read_stream_alloc(struct cbor *c, byte_t major, byte_t **buf)
{
	uint64_t size = read_scope_start(c, major, -1);
	if (!size && INDEF(scope(c)->hdr))
		size = STREAM_INIT_SIZE;
	size_t len = 0;
	*buf = NULL;
realloc:
	*buf = fdap_realloc(*buf, size + 1); /* TODO alloc from a mempool */
	while (!read_scope_end(c, major)) {
		if (len == size) {
			size *= 2;
			goto realloc;
		}
		len += read_stream(c, major, &(*buf)[len], size - len);
	}
	if (size > len && TRIM_STREAMS)
		*buf = realloc(*buf, len + 1);
	(*buf)[len] = '\0';
	return len;
}

uint64_t cbor_read_text_start_len(struct cbor *c)
{
	return read_scope_start(c, MAJOR_TEXT, false);
}

void cbor_read_text_start_indef(struct cbor *c)
{
	read_scope_start(c, MAJOR_TEXT, true);
}

void cbor_read_text_start(struct cbor *c)
{
	read_scope_start(c, MAJOR_TEXT, -1);
}

uint64_t cbor_read_text_alloc(struct cbor *c, char **str)
{
	return read_stream_alloc(c, MAJOR_TEXT, (byte_t **)str);
}

void cbor_text_destroy(struct cbor *c, char *str)
{
	(void) c;
	free(str); // Buď s bohem, řetězče!
}

size_t cbor_read_text(struct cbor *c, char *dst, size_t nbytes)
{
	return read_stream(c, MAJOR_TEXT, (byte_t *)dst, nbytes);
}

bool cbor_read_text_end(struct cbor *c)
{
	return read_scope_end(c, MAJOR_TEXT);
}

uint64_t cbor_read_bytes_start_len(struct cbor *c)
{
	return read_scope_start(c, MAJOR_BYTES, false);
}

void cbor_read_bytes_start_indef(struct cbor *c)
{
	read_scope_start(c, MAJOR_BYTES, true);
}

void cbor_read_bytes_start(struct cbor *c)
{
	read_scope_start(c, MAJOR_BYTES, 1);
}

size_t cbor_read_bytes(struct cbor *c, byte_t *dst, size_t nbytes)
{
	return read_stream(c, MAJOR_BYTES, dst, nbytes);
}

bool cbor_read_bytes_end(struct cbor *c)
{
	return read_scope_end(c, MAJOR_BYTES);
}

uint64_t cbor_read_bytes_alloc(struct cbor *c, byte_t **dst)
{
	return read_stream_alloc(c, MAJOR_BYTES, dst);
}

void cbor_bytes_destroy(struct cbor *c, byte_t *buf)
{
	(void) c;
	free(buf);
}

void cbor_read_array_start(struct cbor *c)
{
	read_scope_start(c, MAJOR_ARRAY, -1);
}

uint64_t cbor_read_array_start_size(struct cbor *c)
{
	return read_scope_start(c, MAJOR_ARRAY, false);
}

void cbor_read_array_start_indef(struct cbor *c)
{
	read_scope_start(c, MAJOR_ARRAY, true);
}

bool cbor_read_array_end(struct cbor *c)
{
	return read_scope_end(c, MAJOR_ARRAY);
}

void cbor_read_map_start(struct cbor *c)
{
	read_scope_start(c, MAJOR_MAP, -1);
}

uint64_t cbor_read_map_start_size(struct cbor *c)
{
	return read_scope_start(c, MAJOR_MAP, false);
}

void cbor_read_map_start_indef(struct cbor *c)
{
	read_scope_start(c, MAJOR_MAP, true);
}

bool cbor_read_map_end(struct cbor *c)
{
	return read_scope_end(c, MAJOR_MAP);
}

cbor_tag_t cbor_read_tag(struct cbor *c)
{
	uint64_t u64;
	check_type(c, read_hdr_u64(c, &u64), MAJOR_TAG, false);
	scope(c)->counter--; /* tags don't count, undo ++ by `read_hdr` */
	if (u64 > CBOR_TAG_MAX)
		err(c, "cannot decode tag > %lu", CBOR_TAG_MAX);
	return (cbor_tag_t)u64;
}

byte_t cbor_read_sval(struct cbor *c)
{
	byte_t hdr = read_hdr(c);
	check_type(c, hdr, MAJOR_7, false);
	byte_t minor = MINOR(hdr);
	if (minor <= DIRECT_VALUE_MAX)
		return minor;
	else if (minor == MINOR_1B)
		return read_byte(c);
	else if (minor <= MINOR_FLOAT_DOUBLE)
		err(c, "float decoding not supported, sorry");
	else if (minor < MINOR_INDEF)
		err(c, "invalid minor bits (%u, 0x%02x)", minor, minor);
	else
		assert(0);
}

bool cbor_read_bool(struct cbor *c)
{
	byte_t sval = cbor_read_sval(c);
	if (sval == CBOR_SVAL_TRUE)
		return true;
	if (sval == CBOR_SVAL_FALSE)
		return false;
	err(c, "simple value 20 (false) or 21 (true) expected, got %u", sval);
}

/*
 * Write `nbytes` bytes to the underlying buffer. If an error occurs during
 * the read operation on the buffer, `err` will be called.
 */
static void write_cbor(struct cbor *c, void *buf, size_t nbytes)
{
	if (iobuf_write(c->buf, buf, nbytes) < 0)
		err(c, "I/O error");
}

/*
 * This function has the same semantics as `write`, but only writes
 * a single byte.
 */
static inline byte_t write_byte(struct cbor *c, byte_t b)
{
	write_cbor(c, &(byte_t[]){ b }, 1); /* TODO use `iobuf_putc` */
	return b;
}

/*
 * Write a header and increase current scope counter.
 */
static byte_t write_hdr(struct cbor *c, byte_t major, byte_t minor)
{
	scope(c)->counter++;
	return write_byte(c, (major << 5) | (minor & 0x1F));
}

static byte_t write_hdr_u64(struct cbor *c, byte_t major, uint64_t u64)
{
	if (u64 <= DIRECT_VALUE_MAX)
		return write_hdr(c, major, (byte_t)u64);
	size_t t = (u64 > UINT8_MAX) + (u64 > UINT16_MAX) + (u64 > UINT32_MAX);
	size_t enc_len = 1 << t;
	byte_t hdr = write_hdr(c, major, MINOR_1B + t);
	uint64_t u64be = htobe64(u64);
	byte_t *u64be_ptr = (byte_t *)&u64be;
	write_cbor(c, &u64be_ptr[sizeof(uint64_t) - enc_len], enc_len);
	return hdr;
}

static void write_int(struct cbor *c, int64_t i64)
{
	if (i64 >= 0)
		write_hdr_u64(c, MAJOR_UINT, (uint64_t)i64);
	else
		write_hdr_u64(c, MAJOR_NEGINT, -i64 - 1);
}

void cbor_write_u8(struct cbor *c, uint8_t u8)
{
	write_hdr_u64(c, MAJOR_UINT, u8);
}

void cbor_write_u16(struct cbor *c, uint16_t u16)
{
	write_hdr_u64(c, MAJOR_UINT, u16);
}

void cbor_write_u32(struct cbor *c, uint32_t u32)
{
	write_hdr_u64(c, MAJOR_UINT, u32);
}

void cbor_write_u64(struct cbor *c, uint64_t u64)
{
	write_hdr_u64(c, MAJOR_UINT, u64);
}

void cbor_write_i8(struct cbor *c, int8_t i8)
{
	write_int(c, i8);
}

void cbor_write_i16(struct cbor *c, int16_t i16)
{
	write_int(c, i16);
}

void cbor_write_i32(struct cbor *c, int32_t u32)
{
	write_int(c, u32);
}

void cbor_write_i64(struct cbor *c, int64_t i64)
{
	write_int(c, i64);
}

static byte_t write_hdr_indef(struct cbor *c, byte_t major)
{
	return write_hdr(c, major, MINOR_INDEF);
}

static void write_break(struct cbor *c)
{
	write_byte(c, BREAK);
}

static void write_scope_end(struct cbor *c, byte_t major)
{
	struct scope *s = scope_check(c, major);
	if (INDEF(s->hdr))
		write_break(c);
	else if (s->counter != s->u64)
		err(c, "%lu items written to %s with size %lu", s->counter,
			strmajor(major), s->u64);
	end_scope(c);
}

void cbor_write_text(struct cbor *c, char *text)
{
	size_t len = strlen(text);
	write_hdr_u64(c, MAJOR_TEXT, len);
	write_cbor(c, (byte_t *)text, len);
}

void cbor_write_text_start_indef(struct cbor *c)
{
	start_scope(c, write_hdr_indef(c, MAJOR_TEXT), 0);
}

void cbor_write_text_end(struct cbor *c)
{
	write_scope_end(c, MAJOR_TEXT);
}

void cbor_write_bytes(struct cbor *c, byte_t *stream, size_t len)
{
	write_hdr_u64(c, MAJOR_BYTES, len);
	write_cbor(c, stream, len);
}

void cbor_write_bytes_start_indef(struct cbor *c)
{
	start_scope(c, write_hdr_indef(c, MAJOR_BYTES), 0);
}

void cbor_write_bytes_end(struct cbor *c)
{
	write_scope_end(c, MAJOR_BYTES);
}

void cbor_write_array_start_size(struct cbor *c, uint64_t len)
{
	start_scope(c, write_hdr_u64(c, MAJOR_ARRAY, len), len);
}

void cbor_write_array_start_indef(struct cbor *c)
{
	start_scope(c, write_hdr_indef(c, MAJOR_ARRAY), 0);
}

void cbor_write_array_end(struct cbor *c)
{
	write_scope_end(c, MAJOR_ARRAY);
}

void cbor_write_map_start_size(struct cbor *c, uint64_t size)
{
	start_scope(c, write_hdr_u64(c, MAJOR_MAP, size), 2 * size);
}

void cbor_write_map_start_indef(struct cbor *c)
{
	start_scope(c, write_hdr_indef(c, MAJOR_MAP), 0);
}

void cbor_write_map_end(struct cbor *c)
{
	write_scope_end(c, MAJOR_MAP);
}

void cbor_write_tag(struct cbor *c, cbor_tag_t tag)
{
	write_hdr_u64(c, MAJOR_TAG, tag);
	scope(c)->counter--; /* tags don't count, undo ++ by `write_hdr` */
}

void cbor_write_sval(struct cbor *c, byte_t sval)
{
	write_hdr_u64(c, MAJOR_7, sval);
}

void cbor_write_bool(struct cbor *c, bool b)
{
	cbor_write_sval(c, b ? CBOR_SVAL_TRUE : CBOR_SVAL_FALSE);
}

/* TODO static-assert that sizeof(etext) < MINOR_1B */

/*
 * Read an item from the stream, store decoded information into `item`. Please
 * note that this operation allocates further memory as needed and that  `item`
 * should always be disposed with a call to `cbor_item_free`.
 */
void cbor_read_item(struct cbor *c, struct cbor_item *item)
{
	cbor_tag_t tag;
	cbor_item_init(item);
	byte_t hdr = peek(c);
	byte_t major = MAJOR(hdr);
	item->type = major;
	switch (major) {
	case MAJOR_UINT:
		item->u64 = cbor_read_u64(c);
		break;
	case MAJOR_NEGINT:
		item->i64 = cbor_read_i64(c);
		break;
	case MAJOR_TEXT:
		if (EMBED_SHORT_TEXT && MINOR(hdr) < sizeof(item->etext)) {
			item->flags |= CBORF_ETEXT;
			cbor_read_text_start_len(c);
			size_t len = cbor_read_text(c, item->etext, sizeof(item->etext));
			cbor_read_text_end(c);
			assert(len == MINOR(hdr));
			item->etext[len] = '\0';
		} else {
			cbor_read_text_alloc(c, &item->text);
		}
		break;
	case MAJOR_BYTES:
		item->u32 = cbor_read_bytes_alloc(c, &item->bytes);
		break;
	case MAJOR_ARRAY:
		item->items = array_new(ARRAY_INIT_SIZE, sizeof(*item->items));
		cbor_read_array_start(c);
		for (item->u32 = 0; !cbor_read_array_end(c); item->u32++)
			cbor_read_item(c, ARRAY_RESERVE(item->items));
		break;
	case MAJOR_MAP:
		item->pairs = array_new(MAP_INIT_SIZE, sizeof(*item->pairs));
		cbor_read_map_start(c);
		for (item->u32 = 0; !cbor_read_map_end(c); item->u32++) {
			struct cbor_pair *p = ARRAY_RESERVE(item->pairs);
			cbor_read_item(c, &p->key);
			cbor_read_item(c, &p->value);
		}
		break;
	case MAJOR_TAG:
		tag = cbor_read_tag(c);
		cbor_read_item(c, item);
		if (can_embed_tagged(item)) {
			item->flags = CBORF_ETAG;
		} else {
			struct cbor_item *tagged = fdap_malloc(sizeof(*tagged));
			*tagged = *item;
			item->type = CBOR_TYPE_TAG;
			item->tagged = tagged;
		}
		item->u32 = tag;
		break;
	case MAJOR_7:
		item->sval = cbor_read_sval(c);
		break;
	default:
		assert(0);
	}
}

/*
 * Return the textual content of a `MAJOR_TEXT` item.
 */
char *cbor_item_get_text(struct cbor_item *item)
{
	assert(item->type == MAJOR_TEXT);
	return (item->flags & CBORF_ETEXT & EMBED_SHORT_TEXT) ? item->etext : item->text;
}

/*
 * Return an escaped copy of the textual content of a `MAJOR_TEXT` item.
 */
char *cbor_item_get_text_escaped(struct cbor_item *item)
{
	char *text = cbor_item_get_text(item);
	struct strbuf buf;
	strbuf_init(&buf, item->u32);
	cbor_text_escape(text, &buf);
	char *escaped = strdup(strbuf_get_string(&buf));
	strbuf_free(&buf);
	return escaped;
}

/*
 * Write `item` to the given CBOR stream `c`.
 */
void cbor_write_item(struct cbor *c, struct cbor_item *item)
{
	if (item->flags & CBORF_ETAG)
		cbor_write_tag(c, item->u32);
	switch (item->type) {
	case MAJOR_UINT:
		cbor_write_u64(c, item->u64);
		break;
	case MAJOR_NEGINT:
		cbor_write_i64(c, item->i64);
		break;
	case MAJOR_TEXT:
		cbor_write_text(c, cbor_item_get_text(item));
		break;
	case MAJOR_BYTES:
		cbor_write_bytes(c, item->bytes, item->u32);
		break;
	case MAJOR_ARRAY:
		cbor_write_array_start_size(c, item->u32);
		for (size_t i = 0; i < item->u32; i++)
			cbor_write_item(c, &item->items[i]);
		cbor_write_array_end(c);
		break;
	case MAJOR_MAP:
		cbor_write_map_start_size(c, item->u32);
		for (size_t i = 0; i < item->u32; i++) {
			cbor_write_item(c, &item->pairs[i].key);
			cbor_write_item(c, &item->pairs[i].value);
		}
		cbor_write_map_end(c);
		break;
	case MAJOR_TAG:
		cbor_write_tag(c, item->u32);
		cbor_write_item(c, item->tagged);
		break;
	case MAJOR_7:
		cbor_write_sval(c, item->sval);
		break;
	default:
		assert(0);
	}
}

/*
 * Dump `item` to the string buffer `str` in CBOR diagnostic notation.
 */
void cbor_item_dump(struct cbor_item *item, struct strbuf *str)
{
	if (item->flags & CBORF_ETAG)
		strbuf_printf(str, "(%u)", item->u32);
	switch (item->type) {
	case MAJOR_UINT:
		strbuf_printf(str, "%lu", item->u64);
		break;
	case MAJOR_NEGINT:
		strbuf_printf(str, "%li", item->i64);
		break;
	case MAJOR_TEXT:
		cbor_text_escape(cbor_item_get_text(item), str);
		break;
	case MAJOR_BYTES:
		strbuf_printf(str, "b'");
		for (size_t i = 0; i < item->u32; i++) {
			strbuf_printf(str, "%02X", item->bytes[i]);
		}
		strbuf_printf(str, "'");
		break;
	case MAJOR_ARRAY:
		strbuf_putc(str, '[');
		for (size_t i = 0; i < item->u32; i++) {
			if (i > 0)
				strbuf_printf(str, ", ");
			cbor_item_dump(&item->items[i], str);
		}
		strbuf_putc(str, ']');
		break;
	case MAJOR_MAP:
		strbuf_putc(str, '{');
		for (size_t i = 0; i < item->u32; i++) {
			if (i > 0)
				strbuf_printf(str, ", ");
			cbor_item_dump(&item->pairs[i].key, str);
			strbuf_printf(str, ": ");
			cbor_item_dump(&item->pairs[i].value, str);
		}
		strbuf_putc(str, '}');
		break;
	case MAJOR_TAG:
		strbuf_printf(str, "(%u)", item->u32);
		cbor_item_dump(item->tagged, str);
		break;
	case MAJOR_7:
		if (item->sval >= CBOR_SVAL_FALSE && item->sval <= CBOR_SVAL_UNDEF)
			strbuf_printf(str, "%s", dump_sval(item->sval));
		else
			strbuf_printf(str, "simple(%u)", item->sval);
		break;
	default:
		DEBUG_EXPR("%u", item->type);
		assert(0);
	}
}

/*
 * Is the `item` either a tag, or an item with a tag embedded?
 */
static bool cbor_item_is_tagged(struct cbor_item *item)
{
	return (item->type == MAJOR_TAG || item->flags & CBORF_ETAG);
}

static cbor_tag_t cbor_item_get_tag(struct cbor_item *item)
{
	if (cbor_item_is_tagged(item))
		return item->u32;
	return CBOR_TAG_NONE;
}

bool cbor_item_strip_tag(struct cbor_item *item, cbor_tag_t *tag)
{
	if (item->type == CBOR_TYPE_TAG) { // regular tagged item
		*tag = item->u32;
		*item = *item->tagged;
		return true;
	}
	if (item->flags & CBORF_ETAG) { // tag is embedded in the item
		*tag = item->u32;
		item->u32 = 0;
		item->flags &= ~CBORF_ETAG;
		return true;
	}
	*tag = CBOR_TAG_NONE;
	return false;
}

#define NUMCMP(a, b) ((a) < (b) ? 1 : ((a) == (b) ? 0 : -1))

/*
 * Compare given items `i1` and `i2`. A negative value, zero and a positive value
 * are returned, if, respectively, `i2` is less than, equal to or greater than `i1`.
 * The sorting rules are best depicted by the source code itself.
 *
 * TODO Major vs type
 */
int cbor_item_cmp(struct cbor_item *i1, struct cbor_item *i2)
{
	if (i1->type != i2->type)
		return i1->type - i2->type;

	/* compare tags of both items */
	struct cbor_item a = *i1, b = *i2;
	cbor_tag_t t, u;
	while (cbor_item_strip_tag(&a, &t) && cbor_item_strip_tag(&b, &u))
		if (t != u)
			return NUMCMP(u, t);
	
	switch (a.type) {
	case MAJOR_UINT:
		return NUMCMP(a.u64, b.u64);
	case MAJOR_NEGINT:
		return NUMCMP(a.i64, b.i64);
	case MAJOR_TEXT:
		return strcmp(cbor_item_get_text(&b), cbor_item_get_text(&a));
	}
	if (a.u32 != b.u32)
		return NUMCMP(a.u32, b.u32);
	int cmp = 0;
	switch (a.type) {
	case MAJOR_BYTES:
		return memcmp(b.bytes, a.bytes, b.u32);
	case MAJOR_ARRAY:
		for (size_t i = 0; i < a.u32; i++)
			if ((cmp = cbor_item_cmp(&a.items[i], &b.items[i])) != 0)
				break;
		return cmp;
	case MAJOR_MAP:
		for (size_t i = 0; i < a.u32; i++) {
			if ((cmp = cbor_item_cmp(&a.pairs[i].key, &b.pairs[i].key)) != 0)
				break;
			if ((cmp = cbor_item_cmp(&a.pairs[i].value, &b.pairs[i].value)) != 0)
				break;
		}
		return cmp;
	case MAJOR_7:
		return NUMCMP(a.sval, b.sval);
	default:
		assert(0);
	}
	return 0;
}
