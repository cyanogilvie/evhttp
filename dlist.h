#ifndef _DLIST_H
#define _DLIST_H

struct dlist_elem {
	void*	next;
	void*	prev;
};

struct dlist {
	struct dlist_elem*	head;
	struct dlist_elem*	tail;
};

void  dlist_prepend(void* dlist, void* elemPtr);
void  dlist_append(void* dlist, void* elemPtr);
void  dlist_remove(void* dlistPtr, void* elemPtr);
void* dlist_pop_head(void* dlist);
void* dlist_pop_tail(void* dlist);
void* dlist_head(void* dlist);
void* dlist_tail(void* dlist);

#endif
