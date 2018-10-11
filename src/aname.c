#include "aname.h"
#include "memory.h"
#include <assert.h>
#include <string.h>

#define ANAME_INIT_SIZE		16
#define PART_SEP		'.'

struct aname *aname_new(char *dotname, struct mempool *mp)
{
	size_t len;
	size_t nparts = 1;
	for (len = 0; dotname[len] != '\0'; len++)
		if (dotname[len] == PART_SEP)
			nparts++;
	struct aname *n;
	size_t struct_size = sizeof(*n) + (nparts - 1) * sizeof(*n->parts);
	size_t alloc_size = struct_size + len + 1;
	n = mempool_alloc(mp, alloc_size);
	char *p = (char *)n + struct_size;
	memcpy(p, dotname, len + 1); // including the null-byte
	for (size_t i = 0; i < nparts; i++) {
		n->parts[i] = p;
		while (*p && *p != PART_SEP)
			p++;
		*p = '\0'; // replaces dot or a null-byte with a null-byte
		p++;
	}
	n->nparts = nparts;
	return n;
}

void aname_dump(struct aname *n, struct strbuf *str)
{
	for (size_t i = 0; i < n->nparts; i++) {
		if (i > 0)
			strbuf_putc(str, PART_SEP);
		strbuf_printf(str, "%s", n->parts[i]);
	}
}

void aname_encode(struct aname *n, struct cbor *c)
{
	struct strbuf buf;
	strbuf_init(&buf, ANAME_INIT_SIZE);
	aname_dump(n, &buf);
	cbor_write_text(c, strbuf_get_string(&buf));
	strbuf_free(&buf);
}

struct aname *aname_decode(struct cbor *c, struct mempool *mp)
{
	size_t len = cbor_read_text_start_len(c);
	char *str = fdap_malloc(len + 1);
	size_t l = 0;
	while (!cbor_read_text_end(c))
		l += cbor_read_text(c, str + l, len - l);
	assert(l == len);
	str[l] = '\0';
	struct aname *n = aname_new(str, mp);
	free(str);
	return n;
}

