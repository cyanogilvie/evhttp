#ifndef _MTAG_H
#define _MTAG_H

/* mtag provider based on https://re2c.org/examples/c/submatch/example_uri_rfc3986.html */
struct mtag {
	struct mtag*	prev;
	long			dist;
};

struct mtagpool {
    struct mtag*		head;
    struct mtag*		next;
    struct mtag*		last;
};

static void mtagpool_clear(struct mtagpool* mtp, struct con_state* c);
static void mtagpool_init(struct mtagpool* mtp);
static void mtagpool_free(struct mtagpool* mtp);
static struct mtag* mtagpool_next(struct mtagpool* mtp);
static void mtag(struct mtag** pmt, const unsigned char* b, const unsigned char* t, struct mtagpool* mtp);

#endif
