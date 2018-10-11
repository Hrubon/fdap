#ifndef LIST_H
#define LIST_H

#include "common.h"
#include <stddef.h>

/*
 * A simple macro providing foreach-like iteration over a linked list.
 * The current node `n' can be modified or freed while the list is walked.
 *
 * TODO Would it be better if I took pointers instead?
 */
#define list_walk(l, n) \
	for (struct lnode *n = (l).head.next, *_n; _n = n ? n->next : NULL, n; n = _n)

/*
 * A list node.
 */
struct lnode
{
	struct lnode *next;
	struct lnode *prev;
};

/*
 * A list.
 */
struct list
{
	struct lnode head;
	struct lnode *last;
};

void list_init(struct list *l);
struct lnode *list_first(struct list *l);

void list_insert(struct list *l, struct lnode *n);
void list_remove(struct list *l, struct lnode *n);
void list_insert_after(struct list *l, struct lnode *n, struct lnode *a);

#endif
