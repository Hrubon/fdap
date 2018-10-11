#include "log.h"
#include "iobuf.h"
#include "list.h" /* TODO for container_of, move and remove */
#include "memory.h"
#include <assert.h>
#include <stdlib.h>

struct iobuf_str
{
	struct iobuf iob;
	size_t size;	/* size of the memory buffer holding all data */
	size_t len;	/* number of bytes written to the buffer */
};

static struct iobuf_str *to_iobuf_str(struct iobuf *iob)
{
	return container_of(iob, struct iobuf_str, iob);
}

/*
 * Resize the string buffer `str` which currently can accommodate for `old_size`
 * bytes of data to be able to hold `new_size` bytes of data. If `str` is `NULL`,
 * a new buffer will be allocated.
 */
static void resize(struct iobuf_str *str, size_t new_size)
{
	str->iob.buf = fdap_realloc(str->iob.buf, new_size);
	str->iob.pos = str->iob.buf + str->size; /* same relative to new buffer */
	str->iob.bptr = str->iob.pos;
	str->iob.bend = str->iob.buf + new_size;
	str->size = new_size;
}

/*
 * Set the back-end pointer to point just after the last written (and flushed)
 * byte.
 */
static ssize_t fill(struct iobuf *buf)
{
	struct iobuf_str *str = to_iobuf_str(buf);
	byte_t *bptr_old = str->iob.bptr;
	str->iob.bptr = str->iob.buf + str->len;
	assert(bptr_old <= str->iob.bptr);
	return str->iob.bptr - bptr_old;
}

/*
 * If current read/write position in the buffer has reached the end of the
 * buffer. In that case, to allow for further writes, we enlarge the buffer to
 * twice its current size while keeping the relative position within the buffer
 * the same. Setting `bptr` to as far as `pos` makes the written data available
 * to future reads.
 */
static int flush(struct iobuf *buf)
{
	struct iobuf_str *str = to_iobuf_str(buf);
	assert(str->iob.bptr <= str->iob.bend);
	if (buf->bptr < buf->pos)
		buf->bptr = buf->pos;
	if (str->iob.pos == str->iob.bend)
		resize(str, 2 * str->size);
	str->len = MAX(str->len, (size_t)(buf->bptr - buf->buf));
	return 0;
}

static void seek(struct iobuf *buf, size_t pos)
{
	struct iobuf_str *str = to_iobuf_str(buf);
	assert(pos < str->size);
	str->iob.pos = str->iob.buf + pos;
	str->iob.bptr = str->iob.pos;
}

static size_t tell(struct iobuf *buf)
{
	struct iobuf_str *str = to_iobuf_str(buf);
	return str->len;
}

static void destroy(struct iobuf *buf)
{
	struct iobuf_str *str = to_iobuf_str(buf);
	iobuf_free(&str->iob);
	resize(str, 0);
	free(str);
}

static struct iobuf_ops iobuf_str_ops = {
	.fill = fill,
	.flush = flush,
	.tell = tell,
	.seek = seek,
	.destroy = destroy,
};

struct iobuf *iobuf_str_new(size_t init_size)
{
	struct iobuf_str *str = fdap_malloc(sizeof(*str));
	iobuf_init(&str->iob);
	str->iob.ops = &iobuf_str_ops;
	str->iob.buf = NULL;
	str->iob.bend = str->iob.buf;
	str->size = 0;
	str->len = 0;
	resize(str, init_size);
	return &str->iob;
}
