#include <string.h>
#include "token_table.h"
#include "log.h"

void tt_init(struct token_table *t, yytname_t *token_names)
{
	t->token_names = token_names;
	tt_reset_tokens(t);
}

void tt_set_token_required(struct token_table *t, int token)
{
	t->token_table[token - MIN_TOKEN] |= 2;
}

bool tt_check_required_tokens(struct token_table *t)
{
	for (int i = 0; i < MAX_TOKEN - MIN_TOKEN; i++) {
		if ((t->token_table[i] & 2) && !(t->token_table[i] & 1)) {
			LOGF(LOG_ERR, "parsing failed: Missing required option %s",
				(*t->token_names)[TOKEN_OFFSET + i]);
			return false;
		}
	}
	return true;
}

bool tt_set_token(struct token_table *t, int token)
{
	int i = token - MIN_TOKEN;
	if (t->token_table[i] & 1) {
		LOGF(LOG_ERR, "parsing failed: Multiple %s option declaration",
			(*t->token_names)[TOKEN_OFFSET + i]);
		return true;
	}
	else {
		t->token_table[i] |= 1;
		return false;
	}
}

void tt_reset_tokens(struct token_table *t)
{
	int len = MAX_TOKEN - MIN_TOKEN;
	memset(t->token_table, '\0', len);
}

