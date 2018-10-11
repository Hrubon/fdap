#include "iobuf.h"
#include "strbuf.h"
#include "log.h"
#include "debug.h"
#include <assert.h>
#include <string.h>

#define DUMPBUF_INIT_SIZE	128
#define COPY_BUFFER_SIZE	(1024 * 1024)

size_t iobuf_avail(struct iobuf *buf)
{
	if (buf->pos > buf->bptr)
		return 0; /* write mode => no data to read */
	return buf->bptr - buf->pos;
}

static inline size_t num_bytes_free(struct iobuf *buf)
{
	return buf->bend - buf->pos;
}

void iobuf_set_debug(struct iobuf *buf, int debug)
{
	buf->debug = debug;
}

void iobuf_init(struct iobuf *buf)
{
	strbuf_init(&buf->dumpbuf, DUMPBUF_INIT_SIZE);
	buf->debug = 0;
	buf->rlimit = IOBUF_NOLIMIT;
}

void iobuf_free(struct iobuf *buf)
{
	strbuf_free(&buf->dumpbuf);
}

/*
 * Print a hex-dump of `len` bytes of data contained in `data`.
 */
static void debug_print(struct iobuf *buf, char *msg, byte_t *data, size_t len)
{
	strbuf_reset(&buf->dumpbuf);
	for (size_t i = 0; i < len; i++) {
		if (i > 0)
			strbuf_putc(&buf->dumpbuf, ' ');
		strbuf_printf(&buf->dumpbuf, "0x%02X", data[i]);
	}
	LOGF(LOG_DEBUG, "%s: %s", msg, strbuf_get_string(&buf->dumpbuf));
}

ssize_t iobuf_read(struct iobuf *buf, byte_t *dst, size_t nbytes)
{
	assert(buf->pos <= buf->bptr);
	size_t total = 0;
	if (buf->rlimit != IOBUF_NOLIMIT)
		nbytes = MIN((ssize_t)nbytes, buf->rlimit);
	while (nbytes > 0) {
		size_t avail = iobuf_avail(buf);
		if (!avail) {
			if (buf->ops->fill(buf) == -1)
				return -1; /* TODO rlimit here, too */
			avail = iobuf_avail(buf);
			if (!avail)
				break; /* EOF reached */
		}
		size_t ncpy = MIN(avail, nbytes);
		assert(ncpy > 0);
		memcpy(dst, buf->pos, ncpy);
		buf->pos += ncpy;
		dst += ncpy;
		total += ncpy;
		nbytes -= ncpy;
	}
	if (buf->debug)
		debug_print(buf, "iobuf_read", (dst - total), total);
	if (buf->rlimit != IOBUF_NOLIMIT)
		buf->rlimit -= total;
	return total;
}

int iobuf_write(struct iobuf *buf, byte_t *src, size_t nbytes)
{
	assert(buf->bptr <= buf->pos);
	if (buf->debug)
		debug_print(buf, "iobuf_write", src, nbytes);
	while (nbytes > 0) {
		size_t nfree = num_bytes_free(buf);
		if (!nfree) {
			if (buf->ops->flush(buf) == -1)
				return -1;
			nfree = num_bytes_free(buf);
			assert(nfree);
		}
		size_t ncpy = MIN(nfree, nbytes);
		assert(ncpy > 0);
		memcpy(buf->pos, src, ncpy);
		buf->pos += ncpy;
		src += ncpy;
		nbytes -= ncpy;
	}
	return 0;
}

ssize_t iobuf_fill_bg(struct iobuf *buf)
{
	if (buf->bptr == buf->bend) { /* we're full */
		if (buf->pos == buf->buf)
			return 0; /* cannot make room for new data */
		size_t off = buf->pos - buf->buf;
		memmove(buf->buf, buf->pos, iobuf_avail(buf));
		buf->bptr -= off;
		buf->pos -= off;
		assert(buf->pos == buf->buf);
	}
	return buf->ops->fill(buf);
}

void iobuf_rlimit(struct iobuf *buf, ssize_t limit)
{
	LOGF(LOG_DEBUG, "Set read limit %li on iobuf %p", limit, buf);
	buf->rlimit = limit;
}

int iobuf_getc(struct iobuf *buf)
{
	int c = 0;
	int ret = iobuf_read(buf, (byte_t *)&c, 1);
	return ret == 1 ? c : -1;
}

void iobuf_ungetc(struct iobuf *buf)
{
	assert(buf->pos > buf->buf); /* guaranteed by previous getc call */
	if (buf->rlimit != IOBUF_NOLIMIT)
		buf->rlimit++;
	buf->pos--;
}

int iobuf_peek(struct iobuf *buf)
{
	int c = iobuf_getc(buf);
	if (c != -1)
		iobuf_ungetc(buf);
	return c;
}

void iobuf_seek(struct iobuf *buf, size_t pos)
{
	assert(buf->ops->seek != NULL);
	iobuf_flush(buf); /* TODO this is sub-optimal for short seeks */
	buf->ops->seek(buf, pos);
	buf->bptr = buf->pos;
}

size_t iobuf_tell(struct iobuf *buf)
{
	assert(buf->ops->tell != NULL);
	return buf->ops->tell(buf);
}

int iobuf_copy(struct iobuf *dst, struct iobuf *src)
{
	byte_t tmp[COPY_BUFFER_SIZE];
	int ret, ret2;
	do {
		ret = iobuf_read(src, tmp, COPY_BUFFER_SIZE);
		if (ret == -1)
			return -1;
		ret2 = iobuf_write(dst, tmp, ret);
		if (ret2 != 0)
			return -1;
	} while (ret > 0);
	return 0;
}

int iobuf_flush(struct iobuf *buf)
{
	if (buf->pos > buf->bptr)
		return buf->ops->flush(buf);
	buf->pos = buf->bptr;
	return 0;
}

void iobuf_destroy(struct iobuf *buf)
{
	buf->ops->destroy(buf);
}
