#include "cbor.h"
#include "test.h"
#include <assert.h>
#include <stdlib.h>
#include <stdnoreturn.h>

struct iobuf *buf;
struct cbor cbor;

static void setup(void)
{
	buf = iobuf_str_new(1024);
	cbor_init(&cbor, buf, errh_throw);
}

static void teardown(void)
{
	cbor_free(&cbor);
	iobuf_destroy(buf);
}

/*
 * TODO Better test is: missing data in the middle of an item. But that requires
 *      some buffer `trunc` support for a clean implementation.
 */
static void test_eof_error(void)
{
	setup();
	try {
		/* try to read from an empty buffer */
		(void) cbor_read_u16(&cbor);
		assert_unreachable();
	}
	teardown();
}

/*
 * Assert that the combination of CBOR_UINT major type (0) and the given
 * minor bits is detected as invalid.
 */
static void test_bad_minor_bits(byte_t minor)
{
	setup();
	byte_t bad_hdr[] = { 0 + minor }; /* major = UINT */
	iobuf_write(buf, bad_hdr, sizeof(bad_hdr));
	iobuf_flush(buf);
	try {
		(void) cbor_read_u8(&cbor);
		assert_unreachable();
	}
	teardown();
}

/*
 * Write a negative integer, then try to decode it as an unsigned integer.
 */
static void test_write_negint_decode_uint(void)
{
	setup();
	cbor_write_i8(&cbor, -1);
	iobuf_flush(buf);
	try {
		(void) cbor_read_u8(&cbor);
		assert_unreachable();
	}
	teardown();
}

/*
 * Helper macro. Write a uint and then try to read it; assert that
 * the reading fails.
 */
#define TEST_UINT_OVERFLOW(u64, read_func) do { \
	setup(); \
	cbor_write_u64(&cbor, u64); \
	iobuf_flush(buf); \
	try { \
		(void) read_func(&cbor); \
		assert_unreachable(); \
	} \
	teardown(); \
} while (0);

static void test_uint_overflows(void)
{
	TEST_UINT_OVERFLOW(UINT8_MAX + 1, cbor_read_u8);
	TEST_UINT_OVERFLOW(UINT16_MAX + 1, cbor_read_u16);
	TEST_UINT_OVERFLOW(UINT32_MAX + 1UL, cbor_read_u32);
}

/*
 * Helper macro. Write an int and then try to read it; assert that
 * the reading fails.
 */
#define TEST_INT_OVERFLOW(i64, read_func) do { \
	setup(); \
	cbor_write_i64(&cbor, i64); \
	iobuf_flush(buf); \
	try { \
		(void) read_func(&cbor); \
		assert_unreachable(); \
	} \
	teardown(); \
} while (0);

/*
 * Try to decode integers which do not fit the return type range.
 */
static void test_int_overflows(void)
{
	TEST_INT_OVERFLOW(INT8_MAX + 1, cbor_read_i8);
	TEST_INT_OVERFLOW(INT8_MIN - 1, cbor_read_i8);
	TEST_INT_OVERFLOW(INT16_MAX + 1, cbor_read_i16);
	TEST_INT_OVERFLOW(INT16_MIN - 1, cbor_read_i16);
	TEST_INT_OVERFLOW(INT32_MAX + 1L, cbor_read_i32);
	TEST_INT_OVERFLOW(INT32_MIN - 1L, cbor_read_i32);
}

/*
 * Try to decode a 64-bit unsigned integer which exceeds INT64_MAX
 * as a signed 64-bit integer.
 */
static void test_decode_u64_as_i64_overflow(void)
{
	setup();
	cbor_write_u64(&cbor, INT64_MAX + 1UL);
	iobuf_flush(buf);
	try {
		(void) cbor_read_i64(&cbor);
		assert_unreachable();
	}
	teardown();
}

/*
 * Try to decode negative integer which is less than INT64_MIN.
 */
static void test_negint_decode_max(void)
{
	setup();
	/* generate a negative integer which is less than `INT64_MIN` */
	byte_t negint_hdr[] = { 0x3B };
	uint64_t big_u64_be = htobe64(labs(INT64_MIN));
	iobuf_write(buf, negint_hdr, sizeof(negint_hdr));
	iobuf_write(buf, (byte_t *)&big_u64_be, sizeof(big_u64_be));
	iobuf_flush(buf);
	try {
		(void) cbor_read_i64(&cbor);
		assert_unreachable();
	}
	teardown();
}

int main(void)
{
	test_eof_error();

	test_bad_minor_bits(0x1C);
	test_bad_minor_bits(0x1D);
	test_bad_minor_bits(0x1E);

	test_uint_overflows();
	test_int_overflows();
	test_decode_u64_as_i64_overflow();
	test_negint_decode_max();

	test_write_negint_decode_uint();

	return EXIT_SUCCESS;
}
