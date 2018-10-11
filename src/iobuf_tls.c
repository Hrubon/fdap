#include <assert.h>

#include "iobuf.h"
#include "list.h" /* TODO for container_of, move and remove */
#include "memory.h"
#include "tls.h"

#include "debug.h"

struct iobuf_tls
{
	struct iobuf iob;
	struct tls_peer *tls_ctx;
	size_t size;
};

static struct iobuf_tls *to_iobuf_tls(struct iobuf *iob)
{
	return container_of(iob, struct iobuf_tls, iob);
}

static ssize_t fill(struct iobuf *buf)
{
	if (buf->pos == buf->bptr)
		buf->pos = buf->bptr = buf->buf;
	struct iobuf_tls *tls_buf = to_iobuf_tls(buf);
	int ret = tls_peer_read(tls_buf->tls_ctx, tls_buf->iob.bptr, tls_buf->iob.bend - tls_buf->iob.bptr);
	if (ret < 0)
		return -1;
	tls_buf->iob.bptr += ret;
	return ret;
}

static int flush(struct iobuf *buf)
{
	struct iobuf_tls *tls_buf = to_iobuf_tls(buf);
	byte_t *src = tls_buf->iob.bptr;
	size_t to_write = tls_buf->iob.pos - src;
	while (to_write > 0) {
		int ret = tls_peer_write(tls_buf->tls_ctx, src, to_write);
		if (ret <= 0)
			return -1;
		to_write -= ret;
		src += ret;
	}
	tls_buf->iob.pos = tls_buf->iob.bptr = tls_buf->iob.buf;
	return 0;
}

static void destroy(struct iobuf *buf)
{
	iobuf_free(buf);
	free(to_iobuf_tls(buf));
}

static struct iobuf_ops iobuf_tls_ops = {
	.fill = fill,
	.flush = flush,
	.tell = NULL,
	.seek = NULL,
	.destroy = destroy,
};

struct iobuf *iobuf_tls_new(struct tls_peer *tls_ctx, size_t buf_size)
{
	struct iobuf_tls *tls_buf = fdap_malloc(sizeof(*tls_buf) + buf_size);
	iobuf_init(&tls_buf->iob);
	tls_buf->tls_ctx = tls_ctx;
	tls_buf->size = buf_size;
	tls_buf->iob.ops = &iobuf_tls_ops;
	tls_buf->iob.buf = (byte_t *)(tls_buf + 1);
	tls_buf->iob.pos = tls_buf->iob.buf;
	tls_buf->iob.bptr = tls_buf->iob.buf;
	tls_buf->iob.bend = tls_buf->iob.buf + tls_buf->size;
	return &tls_buf->iob;
}
