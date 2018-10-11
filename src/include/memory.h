#ifndef MEMORY_H
#define MEMORY_H

#include <stddef.h>

void *fdap_malloc(size_t size);
void *fdap_realloc(void *mem, size_t new_size);

#endif
