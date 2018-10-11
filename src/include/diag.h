#ifndef DIAG_H
#define DIAG_H

#include "cbor.h"
#include "iobuf.h"

struct diag_parser
{
	struct iobuf *in;
	struct strbuf str;
	bool instr;
	int c;
};

void diag_parser_init(struct diag_parser *p, struct iobuf *in);
void diag_parser_free(struct diag_parser *p);

bool diag_parse(struct diag_parser *p, struct cbor_item *item);
bool diag_parse_file(struct cbor_item *item, char *filename);
bool diag_build(struct cbor_item *item, const char *fmt, va_list args);

#endif
