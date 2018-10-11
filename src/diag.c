#include "diag.h"
#include "log.h"
#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <inttypes.h>
#include <string.h>

#define STRBUF_INIT_SIZE	64
#define FILEBUF_INIT_SIZE	256
#define MOD_CHAR	'%'

static int cur(struct diag_parser *p)
{
	return p->c;
}

static bool eof(struct diag_parser *p)
{
	return cur(p) == -1;
}

static int next(struct diag_parser *p)
{
	p->c = iobuf_getc(p->in);
	return cur(p);
}

static void eat_ws(struct diag_parser *p)
{
	while (isspace(cur(p)))
		next(p);
}

static int nextnonw(struct diag_parser *p)
{
	next(p);
	eat_ws(p);
	return cur(p);
}

static bool ctry(struct diag_parser *p, int c)
{
	if (cur(p) != c)
		return false;
	nextnonw(p);
	return true;
}

static int peek(struct diag_parser *p)
{
	return iobuf_peek(p->in);
}

static bool require(struct diag_parser *p, char c)
{
	if (cur(p) != c) {
		LOGF(LOG_ERR, "Got '%c', expected '%c'", cur(p), c);
		return false;
	}
	nextnonw(p);
	return true;
}

static bool parse_i64(struct diag_parser *p, int64_t *out)
{
	bool neg = ctry(p, '-');
	if (!neg)
		ctry(p, '+');
	int64_t i64 = 0;
	if (!isdigit(cur(p))) {
		LOG(LOG_ERR, "Digit expected");
		return false;
	}
	while (!eof(p) && isdigit(cur(p))) {
		i64 = 10 * i64 + (cur(p) - '0');
		nextnonw(p);
	}
	i64 = neg ? -i64 : i64;
	*out = i64;
	return true;
}

static bool parse_number(struct diag_parser *p, struct cbor_item *item)
{
	int64_t i64;
	if (!parse_i64(p, &i64))
		return false;
	cbor_item_set_int(item, i64);
	return true;
}

static bool parse_str(struct diag_parser *p, char **str)
{
	p->instr = true;
	strbuf_reset(&p->str);
	require(p, '\'');
	bool have_delim = false;
	while (!eof(p)) {
		if (cur(p) == '\\') {
			next(p);
			if (eof(p))
				break;
			strbuf_putc(&p->str, cur(p));
			next(p);
			if (eof(p))
				break;
		}
		if (ctry(p, '\'')) {
			have_delim = true;
			break;
		}
		strbuf_putc(&p->str, cur(p));
		next(p);
	}
	if (!have_delim) {
		LOG(LOG_ERR, "String must be delimited by '\''");
		return false;
	}
	p->instr = false;
	*str = strbuf_get_string(&p->str);
	return true;
}

static bool parse_string(struct diag_parser *p, struct cbor_item *item)
{
	char *str;
	if (!parse_str(p, &str))
		return false;
	cbor_item_set_text(item, str);
	return true;
}

static bool char_to_nibble(char c, byte_t *b)
{
	if (!isxdigit(c)) {
		LOG(LOG_ERR, "Only hexadecimal characters are allowed for byte-strings");
		return false;
	}
	if (isdigit(c))
		*b = c - 48;
	else if (isupper(c))
		*b = c - 55;
	else
		*b = c - 87;
	return true;
}

static bool hexstr_to_bytes(char *str, size_t *nbytes)
{
	size_t len = strlen(str);
	if (len == 0)
		return len;
	size_t j = 0;
	for (size_t i = 0; i < len; i++) {
		byte_t n1 = 0, n2 = 0;
		if (i == 0 && len % 2 != 0) {
			n1 = 0;
			if (!char_to_nibble(str[i], &n2))
				return false;
		} else {
			if (!char_to_nibble(str[i], &n1))
				return false;
			if (!char_to_nibble(str[i + 1], &n2))
				return false;
			i++;
		}
		str[j] = n1 << 4 | n2;
		j++;
	}
	*nbytes = j;
	return true;
}

static bool parse_bytes(struct diag_parser *p, struct cbor_item *item)
{
	char *str;
	if (!parse_str(p, &str))
		return false;
	size_t nbytes;
	if (!hexstr_to_bytes(str, &nbytes))
		return false;
	cbor_item_set_bytes(item, (byte_t *)str, nbytes);
	return true;
}

static bool parse_item(struct diag_parser *p, struct cbor_item *item);

static bool parse_array(struct diag_parser *p, struct cbor_item *item)
{
	nextnonw(p);
	bool first = true;
	cbor_item_set_array_start(item);
	while (!eof(p)) {
		if (ctry(p, ']'))
			break;
		if (!first) {
			if (!require(p, ','))
				return false;
		}
		if (ctry(p, ']'))
			break;
		if (!parse_item(p, cbor_item_new_array_item(item)))
			return false;
		first = false;
	}
	cbor_item_set_array_end(item);
	return true;
}

static bool isbare(int c)
{
	if (isalnum(c))
		return true;
	switch (c) {
	case '@':
	case '-':
	case '_':
		return true;
	default:
		return false;
	}
}

static bool parse_bareword(struct diag_parser *p, char **str)
{
	strbuf_reset(&p->str);
	while (!eof(p) && isbare(cur(p))) {
		strbuf_putc(&p->str, cur(p));
		next(p);
	}
	*str = strbuf_get_string(&p->str);
	return true;
}

static bool parse_map(struct diag_parser *p, struct cbor_item *item)
{
	nextnonw(p);
	bool first = true;
	cbor_item_set_map_start(item);
	while (!eof(p)) {
		if (ctry(p, '}'))
			break;
		if (!first) {
			if (!require(p, ','))
				return false;
		}
		if (ctry(p, '}'))
			break;
		struct cbor_pair *pair = cbor_item_new_map_item(item);
		if (!parse_item(p, &pair->key))
			return false;
		if (!require(p, ':'))
			return false;
		if (!parse_item(p, &pair->value))
			return false;
		first = false;
	}
	cbor_item_set_map_end(item);
	return true;
}

static bool parse_tagged(struct diag_parser *p, struct cbor_item *item)
{
	nextnonw(p);
	int64_t i64;
	if (!parse_i64(p, &i64))
		return false;
	if (!require(p, ')'))
		return false;
	cbor_tag_t tag;
	if (i64 > CBOR_TAG_MAX)
		return false;
	tag = (cbor_tag_t)i64;
	struct cbor_item tagged;
	if (!parse_item(p, &tagged))
		return false;
	cbor_item_set_tagged(item, tag, &tagged);
	return true;
}

static bool parse_item(struct diag_parser *p, struct cbor_item *item)
{
	char *w;
	switch (cur(p)) {
	case '+':
	case '-':
	case '0': case '1': case '2': case '3': case '4':
	case '5': case '6': case '7': case '8': case '9':
		return parse_number(p, item);
	case '\'':
		return parse_string(p, item);
	case '[':
		return parse_array(p, item);
	case '{':
		return parse_map(p, item);
	case '(':
		return parse_tagged(p, item);
	case 'b':
		if (peek(p) == '\'') {
			next(p);
			return parse_bytes(p, item);
		}
		/* fall-through */
	default:
		if (!parse_bareword(p, &w))
			return false;
		if (strcmp(w, "simple") == 0 && cur(p) == '(') {
			nextnonw(p);
			int64_t sval;
			if (!parse_i64(p, &sval))
				return false;
			cbor_item_set_sval(item, sval);
			if (!require(p, ')'))
				return false;
			return true;
		} else if (strcmp(w, "false") == 0) {
			cbor_item_set_sval(item, CBOR_SVAL_FALSE);
		} else if (strcmp(w, "true") == 0) {
			cbor_item_set_sval(item, CBOR_SVAL_TRUE);
		} else if (strcmp(w, "null") == 0) {
			cbor_item_set_sval(item, CBOR_SVAL_NULL);
		} else if (strcmp(w, "undef") == 0) {
			cbor_item_set_sval(item, CBOR_SVAL_UNDEF);
		} else {
			cbor_item_set_text(item, w);
		}
		return true;
	}
	assert(0);
	return false;
}

bool diag_parse(struct diag_parser *p, struct cbor_item *item)
{
	cbor_item_init(item);
	bool ret = parse_item(p, item);
	if (cur(p) != -1 && cur(p) != 0) {
		LOGF(LOG_ERR, "Redundant trailing character '%c'\n", cur(p));
		return false;
	}
	return ret;
}

void diag_parser_init(struct diag_parser *p, struct iobuf *in)
{
	p->in = in;
	strbuf_init(&p->str, 128);
	p->instr = false;
	nextnonw(p);
}

void diag_parser_free(struct diag_parser *p)
{
	strbuf_free(&p->str);
}

bool diag_parse_file(struct cbor_item *item, char *filename)
{
	int fd = open(filename, O_RDONLY);
	struct iobuf *buf = iobuf_sock_new(fd, FILEBUF_INIT_SIZE);
	struct diag_parser p;
	diag_parser_init(&p, buf);
	bool ret = diag_parse(&p, item);
	diag_parser_free(&p);
	iobuf_destroy(buf);
	close(fd);
	return ret;
}

bool diag_build(struct cbor_item *item, const char *fmt, va_list args)
{
	bool ret = false;
	char chbuf[2];
	struct strbuf buf;
	strbuf_init(&buf, STRBUF_INIT_SIZE);
	for (size_t i = 0; fmt[i] != '\0'; i++) {
		if (fmt[i] != MOD_CHAR) {
			strbuf_putc(&buf, fmt[i]);
			continue;
		}
		switch (fmt[i + 1]) { /* index valid, at most NUL */
		case MOD_CHAR:
			strbuf_putc(&buf, MOD_CHAR);
			break;
		case 'i':
			strbuf_printf(&buf, "%i", va_arg(args, int));
			break;
		case 's':
			cbor_text_escape(va_arg(args, char *), &buf);
			break;
		case 'c':
			chbuf[0] = va_arg(args, int);
			chbuf[1] = '\0';
			cbor_text_escape(chbuf, &buf);
			break;
		case 'x':
			strbuf_printf(&buf, "b'%s'", va_arg(args, char *));
			break;
		case 'b':
			strbuf_printf(&buf, "%s", va_arg(args, int) ? "true" : "false");
			break;
		case 'v':
			strbuf_printf(&buf, "simple(%u)", va_arg(args, unsigned));
			break;
		case 'd':
			cbor_item_dump(va_arg(args, struct cbor_item *), &buf);
			break;
		default:
			LOGF(LOG_ERR, "Invalid filter format specifier at position %lu", i + 1);
			goto exit2;
		}
		i++;
	}
	size_t len = strbuf_strlen(&buf) + 1;
	struct iobuf *strbuf = iobuf_str_new(len);
	if (iobuf_write(strbuf, (byte_t *)strbuf_get_string(&buf), len) != 0)
		goto exit1;
	iobuf_seek(strbuf, 0);
	struct diag_parser p;
	diag_parser_init(&p, strbuf);
	ret = diag_parse(&p, item);
	diag_parser_free(&p);
exit1:
	iobuf_destroy(strbuf);
exit2:
	strbuf_free(&buf);
	return ret;
}
