#ifndef TRIE_H
#define TRIE_H

#include <stdbool.h>
#include <stddef.h>
#include <inttypes.h>

/*
 * Compressed trie.
 */
struct trie
{
	struct tnode *fake_root;	/* fake root node to simplify code */
};

/*
 * Init the trie `t`.
 */
void trie_init(struct trie *t);

/*
 * Find node with key `key` and return it. If the key is not present in `t`,
 * return `NULL`.
 */
struct tnode *trie_find(struct trie *t, char *key);

/*
 * Does the trie `t` contain the string `key`?
 */
bool trie_contains(struct trie *t, char *key);

/*
 * Insert the key `key` into the trie `t`.
 */
struct tnode *trie_insert(struct trie *t, char *key);

/*
 * Remove the key `key` from the trie `t`.
 */
struct tnode *trie_remove(struct trie *t, char *key);

/*
 * Free the trie `t`.
 */
void trie_free(struct trie *t);

#endif
