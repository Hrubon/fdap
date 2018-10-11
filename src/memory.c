#include "memory.h"
#include <stdlib.h>
#include <err.h>

void *fdap_malloc(size_t size)
{
	return fdap_realloc(NULL, size);
}

void *fdap_realloc(void *mem, size_t new_size)
{
	mem = realloc(mem, new_size);
	if (!mem && new_size > 0)
		errx(EXIT_FAILURE, "cannot allocate %zu bytes of memory", new_size);
	return mem;
}
