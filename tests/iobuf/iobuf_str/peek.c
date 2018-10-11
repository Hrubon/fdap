#include "iobuf.h"
#include "debug.h"
#include <assert.h>
#include <stdlib.h>

#define IOBUF_INIT_SIZE	26

int main(void)
{
	struct iobuf *buf = iobuf_str_new(IOBUF_INIT_SIZE);
	for (char c = 'a'; c < 'z'; c++)
		iobuf_write(buf, (byte_t *)&c, 1);
	iobuf_flush(buf);
	iobuf_seek(buf, 0);
	for (char c = 'a'; c < 'z'; c++) {
		assert(iobuf_peek(buf) == c);
		assert(iobuf_peek(buf) == c); /* peeking twice gives same result */
		assert(iobuf_getc(buf) == c);
		iobuf_ungetc(buf);
		assert(iobuf_getc(buf) == c); /* also moves us forward one byte */
	}
	iobuf_destroy(buf);
	return EXIT_SUCCESS;
}
