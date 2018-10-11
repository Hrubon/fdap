#ifndef IOBUF_H
#define IOBUF_H

/*
 * I/O buffers are useful in situations when you want to read or write large
 * amounts of data without having to worry about the underlying storage
 * mechanism and data buffering.
 *
 * This generic `iobuf` module provides a handle and a set of related
 * operations that act upon a buffer. While your code can depend only on this
 * interface, concrete implementations exist (such as `iobuf_sock` or
 * `iobuf_str`) which take care of the actual reading and writing of data.
 */

#include "common.h"
#include "strbuf.h"
#include <stdbool.h>
#include <unistd.h>

/*
 * If given as argument to `iobuf_rlimit`, cancel all read limits.
 */
#define IOBUF_NOLIMIT	(-1)

/*
 * An I/O buffer.
 */
struct iobuf
{
	struct iobuf_ops *ops;	/* buffer operations */
	byte_t *buf;		/* the I/O buffer */
	byte_t *pos;		/* read/write position within the buffer */
	byte_t *bptr;		/* back-end position */
	byte_t *bend;		/* end of the buffer */
	bool debug;		/* enable debugging of reads and writes? */
	struct strbuf dumpbuf;	/* string buffer for debugging */
	ssize_t rlimit;		/* read limit or `IOBUF_NOLIMIT` */
};

/*
 * I/O buffer operations.
 */
struct iobuf_ops
{
	ssize_t (*fill)(struct iobuf *buf);
	int (*flush)(struct iobuf *buf);
	size_t (*tell)(struct iobuf *buf);
	void (*seek)(struct iobuf *buf, size_t pos);
	void (*destroy)(struct iobuf *buf);
};

/*
 * Read precisely `nbytes` bytes from the I/O buffer `buf` into the
 * user-provided buffer `dst`. Return the number of bytes actually read. This
 * number will be less than `nbytes` if and only if EOF was reached. On error,
 * $-1$ is returned.
 */
ssize_t iobuf_read(struct iobuf *buf, byte_t *dst, size_t nbytes);

/*
 * Write `nbytes` bytes from the user-provided buffer `src` to the I/O buffer
 * `buf`. Returns 0 on success and $-1$ otherwise.
 */
int iobuf_write(struct iobuf *buf, byte_t *src, size_t nbytes);

/*
 * If the I/O buffer `buf` supports it, move current read-write position to
 * the absolute position `pos` within the stream.
 */
void iobuf_seek(struct iobuf *buf, size_t pos);

/*
 * An `ftell`-like function, currently can only return the length of the whole
 * stream (if supported).
 */
size_t iobuf_tell(struct iobuf *buf);

/*
 * Flush the buffer. If the buffer contains read data, this merely prepares it
 * for following writes. If the buffer contains written data, this operation
 * forces a write call to the underlying I/O mechanism (or any equivalent).
 */
int iobuf_flush(struct iobuf *buf);

/*
 * Fill the buffer in the background. This operation can be used to gradually
 * fill the buffer with a sequence of (short) non-blocking reads (using the
 * underlying I/O mechanism), typically in conjunction with an I/O multiplexer
 * such as `epoll`. The buffer can be processed later when enough data was
 * accrued.
 *
 * The operation may trigger a `memmove` inside the buffer if the unread
 * portion of data does not start at the beginning of the buffer in order to
 * make more space.
 *
 * Returns the number of newly buffered bytes (can be 0 if the buffer is full,
 * despite that there's something to read) and $-1$ is returned on error.
 */
ssize_t iobuf_fill_bg(struct iobuf *buf);

/*
 * Set read limit `limit` on the buffer `buf`, making it impossible to read
 * a total of more than `limit` bytes in subsequent read operations. To disable
 * the limit, set `limit` to `IOBUF_NOLIMIT`.
 */
void iobuf_rlimit(struct iobuf *buf, ssize_t limit);

/*
 * Returns the number of bytes ready for ready to be read from the buffer without
 * having to call the underlying I/O mechanism and thus, without blocking.
 */
size_t iobuf_avail(struct iobuf *buf);

/*
 * Get next character from the buffer. Returns $-1$ on error.
 */
int iobuf_getc(struct iobuf *buf);

/*
 * Return last read character back to the buffer. Please note that this operation
 * is only valid immediately after a previous call to `iobuf_getc` (i.e. there
 * must be no interleaving operations performed on this `iobuf`).
 */
void iobuf_ungetc(struct iobuf *buf);

/*
 * Get next character from the buffer without consuming it. Returns $-1$ on error.
 */
int iobuf_peek(struct iobuf *buf);

/*
 * Copy the contents of buffer `src` into the buffer `dst`. The `src` buffer
 * has to support `seek` and `tell` operations.
 */
int iobuf_copy(struct iobuf *dst, struct iobuf *src);

/*
 * Enable or disable the debug mode. If enabled, all data read from/written to
 * this I/O buffer will be logged.
 */
void iobuf_set_debug(struct iobuf *buf, int debug);

struct tls_peer;

void iobuf_init(struct iobuf *iob);
void iobuf_free(struct iobuf *iob);

/*
 * Create a new in-memory buffer with initial size `init_size` bytes. Any data
 * written into this buffer will be stored as a contiguous string in memory.
 * The buffer will grow as needed to accommodate for the writes.
 */
struct iobuf *iobuf_str_new(size_t init_size);

/*
 * Create a new socket-backed buffer. `fd` is the file descriptor of the socket
 * and `size` is the size of the buffer.
 */
struct iobuf *iobuf_sock_new(int fd, size_t size);

/*
 * Create a new buffer which uses the abstractions of the `tls` module to
 * read and write encrypted data. `tls` is the TLS context for the buffer
 * and `size` is the size of the buffer.
 */
struct iobuf *iobuf_tls_new(struct tls_peer *tls, size_t size);

/*
 * Destroy the I/O buffer `buf` obtained by calling one of the constructors
 * above.
 */
void iobuf_destroy(struct iobuf *buf);

#endif
