#include "cbor.h"
#include "test.h"
#include <assert.h>

#define IOBUF_INIT_CAPACITY	400

struct iobuf *buf;
struct cbor cbor;

int main(void)
{
	buf = iobuf_str_new(IOBUF_INIT_CAPACITY);
	cbor_init(&cbor, buf, cbor_errh_default);

	for (size_t i = 0; i < 256; i++)
		cbor_write_sval(&cbor, (byte_t)i);
	iobuf_flush(buf);
	iobuf_seek(buf, 0);
	for (size_t i = 0; i < 256; i++)
		assert(cbor_read_sval(&cbor) == i);

	cbor_free(&cbor);
	iobuf_destroy(buf);
	return EXIT_SUCCESS;
}
