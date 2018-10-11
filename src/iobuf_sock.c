#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "debug.h"
#include "iobuf.h"
#include "list.h" /* TODO for container_of, move and remove */
#include "memory.h"

struct iobuf_sock
{
	struct iobuf iob;
	int fd;
	size_t size;
};

static struct iobuf_sock *to_iobuf_sock(struct iobuf *iob)
{
	return container_of(iob, struct iobuf_sock, iob);
}

static ssize_t fill(struct iobuf *buf)
{
	if (buf->pos == buf->bptr)
		buf->pos = buf->bptr = buf->buf;
	struct iobuf_sock *sock_buf = to_iobuf_sock(buf);
	int ret = read(sock_buf->fd, sock_buf->iob.bptr, sock_buf->iob.bend - sock_buf->iob.bptr);
	if (ret < 0)
		return -1;
	sock_buf->iob.bptr += ret;
	return ret;
}

static int flush(struct iobuf *buf)
{
	struct iobuf_sock *sock_buf = to_iobuf_sock(buf);
	byte_t *src = sock_buf->iob.bptr;
	size_t to_write = sock_buf->iob.pos - src;
	while (to_write > 0) {
		int ret = write(sock_buf->fd, src, to_write);
		if (ret < 0)
			return -1;
		to_write -= ret;
		src += ret;
	}
	sock_buf->iob.pos = sock_buf->iob.bptr = sock_buf->iob.buf;
	return 0;
}

static void destroy(struct iobuf *buf)
{
	iobuf_free(buf);
	free(to_iobuf_sock(buf));
}

static struct iobuf_ops iobuf_sock_ops = {
	.fill = fill,
	.flush = flush,
	.tell = NULL,
	.seek = NULL,
	.destroy = destroy,
};

struct iobuf *iobuf_sock_new(int fd, size_t buf_size)
{
	struct iobuf_sock *sock_buf = fdap_malloc(sizeof(*sock_buf) + buf_size);
	iobuf_init(&sock_buf->iob);
	sock_buf->fd = fd;
	sock_buf->size = buf_size;
	sock_buf->iob.ops = &iobuf_sock_ops;
	sock_buf->iob.buf = (byte_t *)(sock_buf + 1);
	sock_buf->iob.pos = sock_buf->iob.buf;
	sock_buf->iob.bptr = sock_buf->iob.buf;
	sock_buf->iob.bend = sock_buf->iob.buf + sock_buf->size;
	return &sock_buf->iob;
}
