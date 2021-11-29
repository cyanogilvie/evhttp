#ifndef _MTAG_H
#define _MTAG_H

struct mtag {
	struct mtag*	prev;
	long			dist;
};

struct mtagpool {
	struct obstack*		ob;
	void*				start;
};


void mtagpool_init(struct mtagpool* mtp);
void mtagpool_free(struct mtagpool* mtp);
//void mtag(struct mtag** pmt, const unsigned char* b, const unsigned char* t, struct mtagpool* mtp);

static inline void mtag(struct mtag** pmt, const unsigned char* b, const unsigned char* t, struct mtagpool* mtp) //<<<
{
	struct mtag*	mt = obstack_alloc(mtp->ob, sizeof(struct mtag));
	mt->prev = *pmt;
	mt->dist = t - b;
	*pmt = mt;
}

//>>>

#endif
// vim: ft=c foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4
