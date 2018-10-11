/*
 * Automatically growing string buffer with support for formatted printing.
 */

#ifndef STRBUF_H
#define STRBUF_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>

/*
 * The string buffer. Holds accounting data.
 */
struct strbuf
{
	char *str;		/* the buffer itself */
	size_t size;		/* current size of the buffer */
	size_t len;		/* length of the string */
};

/*
 * Initialize the string buffer `buf`. The size of the memory used to store
 * the string will initially be `init_size` bytes.
 */
void strbuf_init(struct strbuf *buf, size_t init_size);

/*
 * Free resources held by `buf`. This includes any strings to which pointers
 * have been obtained by calling `strbuf_get_string`.
 */
void strbuf_free(struct strbuf *buf);

/*
 * Reset buffer `buf` to its initial state when it holds an empty string.
 */
void strbuf_reset(struct strbuf *buf);

/*
 * Append a single character to the string contained in `buf`.
 */
void strbuf_putc(struct strbuf *buf, char c);

void strbuf_prepare_write(struct strbuf *buf, size_t count);

/*
 * Return length of the string held in `buf`.
 */
size_t strbuf_strlen(struct strbuf *buf);

/*
 * Get a pointer to the string held in `buf`. Don't free or write this memory,
 * it's managed by `buf`.
 */
char *strbuf_get_string(struct strbuf *buf);

/*
 * Get a copy of the string held in `buf`. It's the caller's responsibility to
 * `free` this string later.
 */
char *strbuf_strcpy(struct strbuf *buf);

/*
 * This function is semantically equivalent to `printf(3)` with the exception that
 * the resulting string is stored in `buf`, which is resized as needed to fit the
 * appended formatted string.
 */
size_t strbuf_printf(struct strbuf *buf, char *fmt, ...);

/*
 * This function is equivalent to `strbuf_printf`, but accepts a `va_list`
 * of arguments. Instead of appending to the string in `buf`, print at offset
 * given by `offset`.
 */
size_t strbuf_vprintf_at(struct strbuf *buf, size_t offset, char *fmt, va_list args);

/*
 * This function is equivalent to `strubuf_printf`, but prepends the string
 * to the content of `buf` (not overwriting anything that the buffer contains).
 * This function is slow and should be avoided unless performance is not an issue.
 */
size_t strbuf_prepend(struct strbuf *buf, char *fmt, ...);

#endif
