#include "filter.h"
#include "mempool.h"
#include "strbuf.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

#define MEMPOOL_BLOCK_SIZE	1024
#define STRBUF_INIT_SIZE	128

char **table[] = {
	(char *[]){ "x", NULL },
	(char *[]){ "hello", NULL },
	(char *[]){ "a", "b", "c", NULL },
	(char *[]){ "hello", "world", "I", "love", "you!", NULL },
	(char *[]){ "a", "b", "c", "d", "e", "f", "g", "h", "i", NULL },
	NULL,
};

int main(void)
{
	struct strbuf dotbuf;
	struct strbuf prtbuf;
	struct mempool mp;

	mempool_init(&mp, MEMPOOL_BLOCK_SIZE);
	strbuf_init(&dotbuf, STRBUF_INIT_SIZE);
	strbuf_init(&prtbuf, STRBUF_INIT_SIZE);

	for (size_t i = 0; table[i] != NULL; i++) {
		strbuf_reset(&dotbuf);
		size_t nparts = 0;
		for (size_t j = 0; table[i][j] != NULL; j++) {
			if (j > 0)
				strbuf_putc(&dotbuf, '.');
			strbuf_printf(&dotbuf, "%s", table[i][j]);
			nparts++;
		}
		struct aname *a = aname_new(strbuf_get_string(&dotbuf), &mp);
		assert(a->nparts == nparts);
		for (size_t j = 0; j < nparts; j++) {
			assert(strcmp(a->parts[j], table[i][j]) == 0);
		}

		/* also test aname_dump */
		strbuf_reset(&prtbuf);
		aname_dump(a, &prtbuf);
		assert(strcmp(strbuf_get_string(&prtbuf), strbuf_get_string(&dotbuf)) == 0);
	}

	mempool_free(&mp);
	strbuf_free(&dotbuf);
	strbuf_free(&prtbuf);
}
