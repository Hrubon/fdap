#ifndef LOG_H
#define LOG_H

/*
 * Logging utilities.
 */

#include "debug.h"
#include <syslog.h>
#include <stdbool.h>
#include <stdarg.h>
#include <unistd.h>

/*
 * mbedtls debug log levels.
 *
 * TODO Should it be `defined` here? Perhaps there's an include?
 */
#define MBEDTLS_DBG_LEVEL_NODEBUG		0
#define MBEDTLS_DBG_LEVEL_ERROR			1
#define MBEDTLS_DBG_LEVEL_STATE_CHANGE		2
#define MBEDTLS_DBG_LEVEL_INFORMATIONAL		3
#define MBEDTLS_DBG_LEVEL_VERBOSE		4

/*
 * mbedtls target debug level.
 */
#define MBEDTLS_DBG_TARGET_LEVEL		MBEDTLS_DBG_LEVEL_NODEBUG

/*
 * Syslog target logging level.
 */
#define LOG_TARGET_LEVEL			LOG_INFO

/*
 * Set a printf-like `fmt`-formatted message. `flags` is any valid combination
 * of syslog flags, see `syslog(3)`. In debug mode, include `file`, `line` and
 * `func` in the message.
 */
void log_helper(int flags, char *file, size_t line, const char *func, char *fmt, ...);

/*
 * Set a vprintf-like `fmt`-formatted message with args given in `args`.
 * `flags` is any valid combination of syslog flags, see `syslog(3)`. In debug
 * mode, include `file`, `line` and `func` in the message.
 */
void log_vhelper(int flags, char *file, size_t line, const char *func, char *fmt, va_list va);

/*
 * Set a log message `msg`. `flags` is any valid combination of syslog flags,
 * see `syslog(3)`.
 */
#define LOG(flags, msg) \
	log_helper(flags, __FILE__, __LINE__, __func__, msg)

/*
 * Set a printf-like `fmt`-formatted message. `flags` is any valid combination
 * of syslog flags, see `syslog(3)`.
 */
#define LOGF(flags, fmt, ...) \
	log_helper(flags, __FILE__, __LINE__, __func__, fmt, __VA_ARGS__)

/*
 * Set a vprintf-like `fmt`-formatted message with args given in `args`.
 * `flags` is any valid combination of syslog flags, see `syslog(3)`.
 */
#define VLOGF(flags, fmt, args) \
	log_vhelper(flags, __FILE__, __LINE__, __func__, fmt, args)

#endif
