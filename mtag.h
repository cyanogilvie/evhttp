#ifndef _MTAG_H
#define _MTAG_H

/* mtag provider based on https://re2c.org/examples/c/submatch/example_uri_rfc3986.html */
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
struct mtag* mtagpool_next(struct mtagpool* mtp);
void mtag(struct mtag** pmt, const unsigned char* b, const unsigned char* t, struct mtagpool* mtp);

#endif
