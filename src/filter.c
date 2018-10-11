#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cbor.h"
#include "diag.h"
#include "except.h"
#include "fdap.h"
#include "filter.h"
#include "log.h"
#include "memory.h"
#include "mempool.h"

#define FILTER_POOL_BLOCK_SIZE	1024
#define STRBUF_INIT_SIZE	64
#define MOD_CHAR	'%'

static struct filter_node *filter_alloc_node(struct filter *f)
{
	struct filter_node *node = mempool_alloc(&f->pool, sizeof(*node));
	return node;
}

struct filter_node *filter_new_cond(struct filter *f, struct aname *aname,
	enum filter_oper op, struct cbor_item val, bool if_has_then)
{
	struct filter_node *node = filter_alloc_node(f);
	node->type = FILTER_NT_COND;
	node->cond.aname = aname;
	node->cond.op = op;
	node->cond.val = val;
	node->cond.if_has_then = if_has_then;
	return node;
}

struct filter_node *filter_new_unary(struct filter *f, enum filter_oper_un oper,
	struct filter_node *child)
{
	struct filter_node *node = filter_alloc_node(f);
	node->type = FILTER_NT_UNARY;
	node->node_un.oper = oper;
	node->node_un.child = child;
	return node;
}

struct filter_node *filter_new_binary(struct filter *f, enum filter_oper_bin oper,
	struct filter_node *left, struct filter_node *right)
{
	struct filter_node *node = filter_alloc_node(f);
	node->type = FILTER_NT_BINARY;
	node->node_bin.oper = oper;
	node->node_bin.left = left;
	node->node_bin.right = right;
	return node;
}

const char *op_to_str[] = {
	[FILTER_OPER_LT] = "<",
	[FILTER_OPER_LE] = "<=",
	[FILTER_OPER_EQ] = "=",
	[FILTER_OPER_NE] = "!=",
	[FILTER_OPER_GE] = ">=",
	[FILTER_OPER_GT] = ">"
};

void filter_dump_node(struct filter_node *node, struct strbuf *buf)
{
	switch (node->type) {
	case FILTER_NT_COND:
		aname_dump(node->cond.aname, buf);
		const char *op = op_to_str[node->cond.op];
		strbuf_putc(buf, ' ');
		if (node->cond.if_has_then)
			strbuf_putc(buf, '?');
		strbuf_printf(buf, "%s ", op);
		cbor_item_dump(&node->cond.val, buf);
		break;
	case FILTER_NT_UNARY:
		switch (node->node_un.oper) {
			case FILTER_OPU_NOT:
				strbuf_printf(buf, "!");
				break;
		}
		strbuf_printf(buf, "(");
		filter_dump_node(node->node_un.child, buf);
		strbuf_printf(buf, ")");
		break;
	case FILTER_NT_BINARY:
		strbuf_printf(buf, "(");
		filter_dump_node(node->node_bin.left, buf);
		switch (node->node_bin.oper) {
			case FILTER_OPB_AND:
				strbuf_printf(buf, " & ");
				break;
			case FILTER_OPB_OR:
				strbuf_printf(buf, " | ");
				break;
		}
		filter_dump_node(node->node_bin.right, buf);
		strbuf_printf(buf, ")");
		break;
	}
}

void filter_dump(struct filter *f, struct strbuf *buf)
{
	filter_dump_node(f->tree, buf);
}

void filter_init(struct filter *f)
{
	mempool_init(&f->pool, FILTER_POOL_BLOCK_SIZE);
}

bool filter_vbuild(struct filter *f, const char *fmt, va_list args)
{
	int ret = 1;
	struct strbuf buf;
	char chbuf[2];
	strbuf_init(&buf, STRBUF_INIT_SIZE);
	for (size_t i = 0; fmt[i] != '\0'; i++) {
		if (fmt[i] != MOD_CHAR) {
			strbuf_putc(&buf, fmt[i]);
			continue;
		}
		switch (fmt[i + 1]) { /* index valid, at most NUL */
		case MOD_CHAR:
			strbuf_putc(&buf, MOD_CHAR);
			break;
		case 'i':
			strbuf_printf(&buf, "%i", va_arg(args, int));
			break;
		case 's':
			cbor_text_escape(va_arg(args, char *), &buf);
			break;
		case 'c':	
			chbuf[0] = va_arg(args, int);
			chbuf[1] = '\0';
			cbor_text_escape(chbuf, &buf);
			break;
		case 'b':
			strbuf_printf(&buf, "%s", va_arg(args, int) ? "true" : "false");
			break;
		case 'v':
			strbuf_printf(&buf, "s(%u)", va_arg(args, unsigned));
			break;
		case 'f':
			strbuf_putc(&buf, '(');
			filter_dump(va_arg(args, struct filter *), &buf);
			strbuf_putc(&buf, ')');
			break;
		default:
			LOGF(LOG_ERR, "Invalid filter format specifier at position %lu", i + 1);
			goto exit;
		}
		i++;
	}
	ret = filter_parse_string(f, strbuf_get_string(&buf));
exit:
	strbuf_free(&buf);
	return ret == 0;
}

bool filter_build(struct filter *f, const char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	bool ret = filter_vbuild(f, fmt, va);
	va_end(va);
	return ret;
}

static void filter_node_encode(struct filter_node *n, struct cbor *c)
{
	cbor_write_u8(c, n->type);
	switch (n->type) {
	case FILTER_NT_COND:
		aname_encode(n->cond.aname, c);
		cbor_write_bool(c, n->cond.if_has_then);
		cbor_write_u8(c, n->cond.op);
		cbor_write_item(c, &n->cond.val);
		break;
	case FILTER_NT_UNARY:
		cbor_write_u8(c, n->node_un.oper);
		filter_node_encode(n->node_un.child, c);
		break;
	case FILTER_NT_BINARY:
		cbor_write_u8(c, n->node_bin.oper);
		filter_node_encode(n->node_bin.left, c);
		filter_node_encode(n->node_bin.right, c);
		break;
	default:
		LOGF(LOG_ERR, "FDAP filter: Unrecognized filter node type %u", n->type);
		throw;
	}
}

static struct filter_node *filter_node_decode(struct cbor *c, struct filter *f)
{
	enum filter_nodetype type = cbor_read_u8(c);
	struct aname *n;
	enum filter_oper_un oper_un;
	enum filter_oper_bin oper_bin;
	switch (type) {
	case FILTER_NT_COND:
		n = aname_decode(c, &f->pool);
		bool if_has_then = cbor_read_bool(c);
		enum filter_oper op = cbor_read_u8(c);
		struct cbor_item val;
		cbor_read_item(c, &val);
		return filter_new_cond(f, n, op, val, if_has_then);
	case FILTER_NT_UNARY:
		oper_un = cbor_read_u8(c);
		struct filter_node *child = filter_node_decode(c, f);
		return filter_new_unary(f, oper_un, child);
	case FILTER_NT_BINARY:
		oper_bin = cbor_read_u8(c);
		struct filter_node *left = filter_node_decode(c, f);
		struct filter_node *right = filter_node_decode(c, f);
		return filter_new_binary(f, oper_bin, left, right);
	default:
		LOGF(LOG_ERR, "FDAP filter: Unrecognized filter node type %u", type);
		throw;
	}
}

void filter_encode(struct filter *f, struct cbor *c)
{
	filter_node_encode(f->tree, c);
}

void filter_decode(struct filter *f, struct cbor *c)
{
	filter_init(f);
	f->tree = filter_node_decode(c, f);
}

/*
 * Evaluate filter condition `cond` with respect to record `rec`.
 * The `keys` keystore will be used to translate root-level keys to attribute IDs.
 */
static bool eval_cond(struct filter_cond *cond, struct record *rec, struct keystore *keys)
{
	struct cbor_item *val = record_getby_aname(rec, cond->aname, keys);
	if (!val)
		return cond->if_has_then;
	int cmp = cbor_item_cmp(&cond->val, val);
	switch (cond->op) {
	case FILTER_OPER_LT:
		return cmp < 0;
	case FILTER_OPER_LE:
		return cmp <= 0;
	case FILTER_OPER_EQ:
		return cmp == 0;
	case FILTER_OPER_NE:
		return cmp != 0;
	case FILTER_OPER_GE:
		return cmp >= 0;
	case FILTER_OPER_GT:
		return cmp > 0;
	default:
		assert(0);
	}
}

/*
 * Return `true` iff the record `rec` matches filter subtree rooted at `n`.
 * The `kyes` keystore will be used to translate root-level keys to attribute IDs.
 */
static bool match(struct filter_node *n, struct record *rec, struct keystore *keys)
{
	bool l, r, b;
	switch (n->type) {
	case FILTER_NT_UNARY:
		b = match(n->node_un.child, rec, keys);
		switch (n->node_un.oper) {
		case FILTER_OPU_NOT:
			return !b;
		default:
			assert(0);
		}
	case FILTER_NT_BINARY:
		l = match(n->node_bin.left, rec, keys);
		r = match(n->node_bin.right, rec, keys);
		switch (n->node_bin.oper) {
		case FILTER_OPB_AND:
			return l && r;
		case FILTER_OPB_OR:
			return l || r;
		default:
			assert(0);
		}
	case FILTER_NT_COND:
		return eval_cond(&n->cond, rec, keys);
	default:
		assert(0);
	}
}

bool filter_match(struct filter *f, struct record *rec, struct keystore *keys)
{
	return match(f->tree, rec, keys);
}

void filter_free(struct filter *f)
{
	mempool_free(&f->pool);
}
