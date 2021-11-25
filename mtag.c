#include "evhttpInt.h"

static void mtagpool_clear(struct mtagpool* mtp, struct con_state* c) //<<<
{
	mtp->next = mtp->head;
	/*!mtags:re2c:http format = "\tc->@@{tag} = NULL;\n"; */
}

//>>>
static void mtagpool_init(struct mtagpool* mtp) //<<<
{
	static const unsigned	size = 1024 * 1024;

	mtp->head = (struct mtag*)malloc(size * sizeof(struct mtag));
	mtp->next = mtp->head;
	mtp->last = mtp->head + size;
}

//>>>
static void mtagpool_free(struct mtagpool* mtp) //<<<
{
	free(mtp->head);
	mtp->head = mtp->next = mtp->last = NULL;
}

//>>>
static struct mtag* mtagpool_next(struct mtagpool* mtp) //<<<
{
	unsigned		size;
	struct mtag*	head;

	if (mtp->next < mtp->last) return mtp->next++;

	size = mtp->last - mtp->head;
	head = (struct mtag*)malloc(2 * size * sizeof(struct mtag));
	memcpy(head, mtp->head, size * sizeof(struct mtag));
	free(mtp->head);
	mtp->head = head;
	mtp->next = head + size;
	mtp->last = head + size * 2;

	return mtp->next++;
}

//>>>
static void mtag(struct mtag** pmt, const unsigned char* b, const unsigned char* t, struct mtagpool* mtp) //<<<
{
	struct mtag*	mt = mtagpool_next(mtp);
	mt->prev = *pmt;
	mt->dist = t - b;
	*pmt = mt;
}

//>>>

// vim: ft=c foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4
