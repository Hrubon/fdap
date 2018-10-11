#include "iobuf.h"
#include "debug.h"
#include <assert.h>

#define IOBUF_INIT_SIZE		7002
#define RX_BUF_SIZE		173

struct iobuf *buf;
byte_t rx[RX_BUF_SIZE];

static void test_rlimit(size_t rlimit)
{
	iobuf_seek(buf, 0);
	iobuf_rlimit(buf, rlimit);
	size_t total = 0;
	while (1) {
		int ret = iobuf_read(buf, rx, RX_BUF_SIZE);
		assert(ret != -1);
		if (ret > 0)
			total += ret;
		else
			break;
	}
	assert(total == rlimit);
}

int main(void)
{
	buf = iobuf_str_new(IOBUF_INIT_SIZE);
	byte_t garbage[IOBUF_INIT_SIZE];
	assert(iobuf_write(buf, garbage, IOBUF_INIT_SIZE) == 0);
	iobuf_flush(buf);
	test_rlimit(0);
	test_rlimit(1);
	test_rlimit(RX_BUF_SIZE);
	test_rlimit(RX_BUF_SIZE + 1);
	test_rlimit(3 * RX_BUF_SIZE + 7);
	test_rlimit(IOBUF_INIT_SIZE);
	iobuf_destroy(buf);
}
