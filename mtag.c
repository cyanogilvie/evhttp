#include "evhttpInt.h"

void mtagpool_init(struct mtagpool* mtp) //<<<
{
	mtp->ob = obstack_pool_get(OBSTACK_POOL_SMALL);
	mtp->start = obstack_alloc(mtp->ob, 1);
}

//>>>
void mtagpool_free(struct mtagpool* mtp) //<<<
{
	obstack_pool_release(mtp->ob);
}

//>>>

// vim: ft=c foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4
