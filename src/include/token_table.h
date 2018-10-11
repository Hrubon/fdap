#ifndef TOKEN_TABLE_H
#define TOKEN_TABLE_H

#include <stdbool.h>

#define MIN_TOKEN 258
#define MAX_TOKEN 282
#define TOKEN_OFFSET 3

typedef const char *const yytname_t[];

struct token_table
{
	char token_table[MAX_TOKEN - MIN_TOKEN];
	yytname_t *token_names;
};

void tt_init(struct token_table *t, yytname_t *token_names);
void tt_set_token_required(struct token_table *t, int token);
bool tt_check_required_tokens(struct token_table *t);
bool tt_set_token(struct token_table *t, int token);
void tt_reset_tokens(struct token_table *t);

#endif
