#ifndef _OBSTACK_POOL_H
#define _OBSTACK_POOL_H

enum obstack_pool_estimate {
	OBSTACK_POOL_SMALL,			// A few pages
	OBSTACK_POOL_MEDIUM			// A MB or more
};

struct obstack* obstack_pool_get(enum obstack_pool_estimate est);
void obstack_pool_release(struct obstack* ob);
void obstack_pool_groom(uint64_t now);

#endif
