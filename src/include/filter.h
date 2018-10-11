#ifndef FILTER_H
#define FILTER_H

#include "cbor.h"
#include "mempool.h"
#include "record.h"
#include "strbuf.h"
#include <stdio.h>

/*
 * Represents filter within FDAP queries
 */
struct filter
{
	struct mempool pool;
	struct filter_node *tree;
};

/*
 * Filter condition operator.
 */
enum filter_oper
{
	FILTER_OPER_LT,
	FILTER_OPER_LE,
	FILTER_OPER_EQ,
	FILTER_OPER_NE,
	FILTER_OPER_GE,
	FILTER_OPER_GT,
	FILTER_OPER_HAS,
};

/*
 * Filter-tree condition (e.g. user.name = 'Medvěd')
 */
struct filter_cond
{
	struct aname *aname;
	bool if_has_then;
	enum filter_oper op;
	struct cbor_item val;
};

/*
 * Unary operations.
 */
enum filter_oper_un
{
	FILTER_OPU_NOT,
};

/*
 * Filter-tree unary node.
 */
struct filter_node_un
{
	enum filter_oper_un oper;
	struct filter_node *child;
};

/*
 * Binary operations.
 */
enum filter_oper_bin
{
	FILTER_OPB_AND,
	FILTER_OPB_OR
};

/*
 * Filter-tree binary node.
 */
struct filter_node_bin
{
	enum filter_oper_bin oper;
	struct filter_node *left;
	struct filter_node *right;
};

enum filter_nodetype
{
	FILTER_NT_COND,
	FILTER_NT_UNARY,
	FILTER_NT_BINARY
};

/*
 * Generic filter-tree node.
 */
struct filter_node
{
	enum filter_nodetype type;
	union
	{
		struct filter_cond cond;
		struct filter_node_un node_un;
		struct filter_node_bin node_bin;
	};
};

/*
 * Filter tree API
 */
struct filter_node *filter_new_cond(struct filter *f, struct aname *aname,
	enum filter_oper op, struct cbor_item val, bool if_has_then);
struct filter_node *filter_new_unary(struct filter *f, enum filter_oper_un oper, struct filter_node *child);
struct filter_node *filter_new_binary(struct filter *f, enum filter_oper_bin oper, struct filter_node *left, struct filter_node *right);
void filter_dump_node(struct filter_node *node, struct strbuf *buf);

/*
 * Filter basic operations
 */
void filter_init(struct filter *f);
bool filter_vbuild(struct filter *f, const char *fmt, va_list args);
bool filter_build(struct filter *f, const char *fmt, ...);
void filter_dump(struct filter *f, struct strbuf *buf);
void filter_encode(struct filter *f, struct cbor *c);
void filter_decode(struct filter *f, struct cbor *c);
void filter_free(struct filter *f);

/*
 * Filter parsing (see filter_lexer.l for definitions)
 */
int filter_parse_string(struct filter *filter, const char *str);
int filter_parse_file(struct filter *filter, FILE *file);

/*
 * Does the filter `f` match the record `rec`? The `kyes` keystore will be used
 * to translate root-level keys to attribute IDs.
 */
bool filter_match(struct filter *f, struct record *rec, struct keystore *keys);

#endif
