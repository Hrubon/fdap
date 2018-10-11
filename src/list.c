#include "list.h"
#include "log.h"
#include <assert.h>

void list_init(struct list *l)
{
	l->head.next = NULL;
	l->head.prev = NULL;
	l->last = &l->head;
}

void list_insert_after(struct list *l, struct lnode *n, struct lnode *a)
{
	assert(n != &l->head);
	n->prev = a;
	n->next = a->next;
	a->next = n;
	if (n->next)
		n->next->prev = n;
	else
		l->last = n;
	
}

void list_insert(struct list *l, struct lnode *n)
{
	list_insert_after(l, n, l->last);
}

void list_remove(struct list *l, struct lnode *n)
{
	assert(n != &l->head);
	if (l->last == n)
		l->last = n->prev;
	n->prev->next = n->next;
	if (n->next)
		n->next->prev = n->prev;
	n->next = NULL;
	n->prev = NULL;
}

struct lnode *list_first(struct list *l)
{
	return l->head.next;
}
