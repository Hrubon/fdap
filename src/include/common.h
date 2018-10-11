#ifndef COMMON_H
#define COMMON_H

#define container_of(ptr, type, member) \
	((type *)((unsigned char *)ptr - offsetof(type, member)))

#define MIN(a, b)	((a) < (b) ? (a) : (b))
#define MAX(a, b)	((a) > (b) ? (a) : (b))

typedef unsigned char	byte_t;

#endif
