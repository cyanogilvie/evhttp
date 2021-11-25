#ifndef _DLIST_H
#define _DLIST_H

struct dlist_elem {
	struct dlist*	next;
	struct dlist*	prev;
};

struct dlist {
	struct dlist*	head;
	struct dlist*	tail;
};

void  dlist_prepend(struct dlist* dlist, void* elemPtr);
void  dlist_append(struct dlist* dlist, void* elemPtr);
void* dlist_pop_head(struct dlist* dlist);
void* dlist_pop_tail(struct dlist* dlist);
void* dlist_head(struct dlist* dlist);
void* dlist_tail(struct dlist* dlist);

#endif
