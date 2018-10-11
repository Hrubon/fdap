#ifndef ANAME_H
#define ANAME_H

#include "cbor.h"
#include "mempool.h"
#include "strbuf.h"

/*
 * Attribute name. Convenient representation of a dot-separated
 * path, such as `some.field.name`.
 */
struct aname
{
	size_t nparts;	/* number of parts of the name */
	char *parts[1];	/* the parts themselves (there's at least one) */
};

/*
 * Given a dot-separated path `dotname`, construct an `aname`. The `dotname`
 * will be copied to `mp`, as well as the returned `aname` object.
 */
struct aname *aname_new(char *dotname, struct mempool *mp);

/*
 * Print the dot-separated path that `n` represents to `str`.
 */
void aname_dump(struct aname *n, struct strbuf *str);
void aname_encode(struct aname *n, struct cbor *c);
struct aname *aname_decode(struct cbor *c, struct mempool *mp);

#endif
