#include <stddef.h>
#include "dlist.h"

void dlist_prepend(void* dlistPtr, void* elemPtr) //<<<
{
	struct dlist*		dlist = dlistPtr;
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
void dlist_append(void* dlistPtr, void* elemPtr) //<<<
{
	struct dlist*		dlist = dlistPtr;
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
void dlist_remove(void* dlistPtr, void* elemPtr) //<<<
{
	struct dlist*		dlist = dlistPtr;
	struct dlist_elem*	elem = elemPtr;

	if (elem->prev) {
		struct dlist_elem*	elem_prev = elem->prev;
		elem_prev->next = elem->next;
	} else {
		// elem was the head
		dlist->head = elem->next;
	}

	if (elem->next) {
		struct dlist_elem*	elem_next = elem->next;
		elem_next->prev = elem->prev;
	} else {
		// elem was the tail
		dlist->tail = elem->prev;
	}
}

//>>>
void* dlist_pop_head(void* dlistPtr) //<<<
{
	struct dlist*	dlist = dlistPtr;
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
void* dlist_pop_tail(void* dlistPtr) //<<<
{
	struct dlist*		dlist = dlistPtr;
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
void* dlist_head(void* dlistPtr) //<<<
{
	struct dlist*	dlist = dlistPtr;
	return dlist->head;
}

//>>>
void* dlist_tail(void* dlistPtr) //<<<
{
	struct dlist*	dlist = dlistPtr;
	return dlist->tail;
}

//>>>

// vim: ft=c foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4
