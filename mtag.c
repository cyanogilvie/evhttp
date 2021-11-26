#include "evhttpInt.h"

void mtagpool_clear(struct mtagpool* mtp, struct con_state* c) //<<<
{
	obstack_free(mtp->ob, mtp->start);
	mtp->start = obstack_alloc(mtp->ob, 1);
	/*!mtags:re2c:http format = "\tc->@@{tag} = NULL;\n"; */
}

//>>>
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
struct mtag* mtagpool_next(struct mtagpool* mtp) //<<<
{
	return obstack_alloc(mtp->ob, sizeof(struct mtag));
}

//>>>
void mtag(struct mtag** pmt, const unsigned char* b, const unsigned char* t, struct mtagpool* mtp) //<<<
{
	struct mtag*	mt = mtagpool_next(mtp);
	mt->prev = *pmt;
	mt->dist = t - b;
	*pmt = mt;
}

//>>>

// vim: ft=c foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4
