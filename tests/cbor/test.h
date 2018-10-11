#ifndef TEST_H
#define TEST_H

#include "log.h"
#include "except.h"
#include <assert.h>

#define test(name)	void test_##name(void)

static noreturn void assert_unreachable(void)
{
	assert(0);
}

static void errh_throw(struct cbor *cbor)
{
	(void) cbor;
	LOGF(LOG_DEBUG, "Caught CBOR error: %s", cbor_strerror(cbor));
	throw;
}

#endif
