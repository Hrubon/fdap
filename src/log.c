#include "log.h"
#include "strbuf.h"
#include <stdarg.h>
#include <unistd.h>

#define FILE_NAME_MAXLEN	24
#define FUNC_NAME_MAXLEN	24
#define VT100_INFO_COLOR	36
#define VT100_NOTICE_COLOR	33
#define VT100_ERR_COLOR		31

static const char *level_to_str(int level)
{
	switch (level) {
	case LOG_EMERG:
		return "EMERG";
	case LOG_ALERT:
		return "ALERT";
	case LOG_CRIT:
		return "CRIT";
	case LOG_ERR:
		return "ERR";
	case LOG_WARNING:
		return "WARNING";
	case LOG_NOTICE:
		return "NOTICE";
	case LOG_INFO:
		return "INFO";
	case LOG_DEBUG:
		return "DEBUG";
	}
	assert(0);
}

void log_vhelper(int flags, char *file, size_t line, const char *func, char *fmt, va_list va)
{
	int level = LOG_TARGET_LEVEL;
	if (flags > level)
		return;

	struct strbuf msg;
	strbuf_init(&msg, 96);

	if (DEBUG)
		strbuf_printf(&msg, "*** %-7s ***", level_to_str(flags));
	strbuf_printf(&msg, "%*s % 4d", FILE_NAME_MAXLEN, file, line);
	strbuf_printf(&msg, "%*s    ", FUNC_NAME_MAXLEN, func);
	strbuf_vprintf_at(&msg, strbuf_strlen(&msg), fmt, va);
	strbuf_printf(&msg, "\n");
	if (DEBUG) {
		if (isatty(STDERR_FILENO)) { /* colorize errors */
			if (flags <= LOG_ERR)
				strbuf_prepend(&msg, "\x1B[%im", VT100_ERR_COLOR);
			else if (flags <= LOG_NOTICE)
				strbuf_prepend(&msg, "\x1B[%im", VT100_NOTICE_COLOR);
			else if (flags <= LOG_INFO)
				strbuf_prepend(&msg, "\x1B[%im", VT100_INFO_COLOR);
			strbuf_printf(&msg, "\x1B[0m");
		}
		fprintf(stderr, strbuf_get_string(&msg));
	}
	else {
		syslog(flags, strbuf_get_string(&msg));
	}
	strbuf_free(&msg);
}

void log_helper(int flags, char *file, size_t line, const char *func, char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	log_vhelper(flags, file, line, func, fmt, va);
	va_end(va);
}
