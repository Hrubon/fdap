#ifndef DEBUG_H
#define DEBUG_H

#include <assert.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>

#ifndef DEBUG
#define DEBUG	1
#endif

#define DEBUG_PRINTF(fmt, ...) do { \
	if (DEBUG) \
		fprintf(stderr, "*** DEBUG   ***%*s % 4d%*s    " fmt "\n", \
				24, __FILE__, __LINE__, 24, __func__, __VA_ARGS__); \
} while (0)

#define DEBUG_MSG(msg)			DEBUG_PRINTF("%s", msg)
#define DEBUG_EXPR(formatter, expr)	DEBUG_PRINTF(#expr " = " formatter, (expr))
#define DEBUG_TRACE			DEBUG_PRINTF("Control reached %s", __func__)
#define TMP_ASSERT(expr)		assert(expr)
#define TODO_ASSERT(expr)		assert(expr)

#endif
