#include "trie.h"
#include <assert.h>
#include <stdlib.h>
#include <time.h>

#define KEY_MAX_LEN		6
#define LONG_KEY_TEST_SIZE	1024

int inc(char k[KEY_MAX_LEN])
{
	int i;
	for (i = KEY_MAX_LEN - 1; i >= 0; i--) {
		if (++k[i] <= 'c')
			break;
		k[i] = 'a';
	}
	return i >= 0;
}

static void test_seq(void)
{
	struct trie yes, no;
	trie_init(&yes);
	trie_init(&no);
	char key[KEY_MAX_LEN + 1];
	for (size_t i = 0; i < KEY_MAX_LEN; i++)
		key[i] = 'a';
	key[KEY_MAX_LEN] = '\0';

	do {
		trie_insert((rand() % 2) ? &yes : &no, key);
	} while (inc(key));

	do {
		if (trie_contains(&yes, key))
			assert(!trie_contains(&no, key));
		if (trie_contains(&no, key))
			assert(!trie_contains(&yes, key));
	} while (inc(key));
	trie_free(&yes);
	trie_free(&no);
}

static void test_long_keys(void)
{
	struct trie t;
	trie_init(&t);
	char key[KEY_MAX_LEN];
	for (size_t n = 0; n < LONG_KEY_TEST_SIZE; n++) {
		size_t len = rand() % KEY_MAX_LEN;
		for (size_t i = 0; i < len; i++)
			key[i] = 'a' + (rand() % ('z' - 'a'));
		key[len] = '\0';
		struct tnode *n = trie_insert(&t, key);
		assert(n == trie_find(&t, key));
		assert(n == trie_insert(&t, key));
	}
	trie_free(&t);
}

#include <stdio.h>

#define ENGLISH_WORD_MAX	32

static void test_english_words(void)
{
	struct trie t;
	FILE *f = fopen("tests/assets/words.txt", "r");
	assert(f != NULL);
	size_t size = ENGLISH_WORD_MAX + 1;
	char *word = malloc(size);
	assert(word);
	ssize_t len;
	trie_init(&t);
	while ((len = getline(&word, &size, f)) > 0) {
		word[len - 1] = '\0'; /* trim the new-line */
		trie_insert(&t, word);
		assert(trie_contains(&t, word));
	}
	free(word);
	fclose(f);
	trie_free(&t);
}

int main(void)
{
	srand(time(NULL));
	test_seq();
	test_long_keys();
	test_english_words();
	return EXIT_SUCCESS;
}
