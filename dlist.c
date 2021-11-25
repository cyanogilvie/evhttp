#include "dlist.h"

void dlist_prepend(struct dlist* dlist, void* elemPtr) //<<<
{
	struct dlist_elem*	elem = elemPtr;

	if (dlist->head) {
		dlist->head->prev = elem;
		elem->next = dlist->head;
		dlist->head = elem;
	} else {
		dlist->head = dlist->tail = elem;
		elem->next = NULL;
		elem->prev = NULL;
	}
}

//>>>
void dlist_append(struct dlist* dlist, void* elemPtr) //<<<
{
	struct dlist_elem*	elem = elemPtr;

	if (dlist->tail) {
		dlist->tail->next = elem;
		elem->prev = dlist->tail;
		dlist->tail = elem;
	} else {
		dlist->head = dlist->tail = elem;
		elem->next = NULL;
		elem->prev = NULL;
	}
}

//>>>
void* dlist_pop_head(struct dlist* dlist) //<<<
{
	struct dlist_elem*	elem = NULL;

	if (dlist->head) {
		elem = dlist->head;

		dlist->head = elem->next;
		elem->next = NULL;

		if (dlist->tail == elem) dlist->tail = NULL;
	}

	return elem;
}

//>>>
void* dlist_pop_tail(struct dlist* dlist) //<<<
{
	struct dlist_elem*	elem = NULL;

	if (dlist->tail) {
		elem = dlist->tail;

		dlist->tail = elem->prev;
		elem->prev = NULL;

		if (dlist->head == elem) dlist->head = NULL;
	}

	return elem;
}

//>>>
void* dlist_head(struct dlist* dlist) //<<<
{
	return dlist->head;
}

//>>>
void* dlist_tail(struct dlist* dlist) //<<<
{
	return dlist->tail;
}

//>>>

// vim: ft=c foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4
