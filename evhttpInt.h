#ifndef _EVHTTPINT_H
#define _EVHTTPINT_H

#define _GNU_SOURCE
#define EV_MULTIPLICITY	1

#define obstack_chunk_alloc	malloc
#define obstack_chunk_free	free

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>
#include <threads.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <netdb.h>
#include <math.h>
#include <obstack.h>
#include <signal.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <x86intrin.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include "ev.h"
#include "fmtshim.h"
#include "murmur3shim.h"
#include "dlist.h"
#include "mtag.h"
#include "obstack_pool.h"

extern thread_local int	t_cpu_cycles_fd;

struct listensock_queue {
	struct listensock* head;
	struct listensock* tail;
};

struct listensock {
	struct ev_io		accept_watcher;		// Must be first
	struct msg_queue*	msg_queue;
	struct listensock*	next;
};

enum con_role {
	CON_ROLE_SERVER,
	CON_ROLE_CLIENT
};

struct con_watch {
	struct ev_io		w;					// Must be first
	struct ev_loop*		loop;
	enum con_role		role;
	struct listensock*	listener;
};

/*
enum ev_type {
	EV_PIPE_NEWCON,
	EV_PIPE_REQ,
	EV_PIPE_CONCLOSED
};

struct ev_pipe_event {
	enum ev_type	type;
	void*			data;
};
*/

enum con_status {
	CON_STATUS_UNDEF=0,
	CON_STATUS_WAITING,
	CON_STATUS_OVERFLOW,
	CON_STATUS_ERROR,
	CON_STATUS_BODY,
	CON_STATUS_BODY_DONE
};

enum ev_methods {
	METHOD_UNSPECIFIED=0,
	METHOD_GET,
	METHOD_HEAD,
	METHOD_POST,
	METHOD_PUT,
	METHOD_DELETE,
	METHOD_CONNECT,
	METHOD_OPTIONS,
	METHOD_TRACE,
	METHOD_CUSTOM			// Custom method specified, string is in con_state.custom_method
};

enum con_flags {
	CON_CLOSE,
	CON_KEEP_ALIVE,
	CON_UPGRADE
};

enum te_types {
	TE_CHUNKED,
	TE_COMPRESS,
	TE_DEFLATE,
	TE_GZIP,
	TE_TRAILERS
};

struct te_accept {
	enum te_types	type;
	float			rank;
};

struct cookie {
	struct cookie*		next;
	unsigned char*		name;
	unsigned char*		value;
};

#define COOKIE_FLAG_HTTPONLY	(1<<0)
#define COOKIE_FLAG_SECURE		(1<<1)
struct set_cookie {
	struct set_cookie*	next;
	unsigned char*		name;
	unsigned char*		value;
	unsigned char*		path;			// NULL if not set
	unsigned char*		domain;			// NULL if not set
	int64_t				max_age;		// -1 if not set
	unsigned char*		expires;		// NULL if not set
	unsigned char		flags;			// Bitset of COOKIE_FLAG_*
};

struct dl_token {
	struct dlist_elem	dl;
	unsigned char*		token;
};

struct media_type_param {
	struct media_type_param*	next;
	unsigned char*	name;
	unsigned char*	value;
};

struct media_type {
	unsigned char*				media_type;
	struct media_type_param*	params;
};

enum body_len {
	BODY_LEN_NOTSET=0,
	BODY_LEN_NONE,
	BODY_LEN_CHUNKED,
	BODY_LEN_CONTENT_LENGTH,
	BODY_LEN_EOF
};

enum body_storage {
	BODY_STORAGE_NONE=0,
	BODY_STORAGE_BORROWED,		// Points at memory owned by someone else (probably the c->ob)
	BODY_STORAGE_MALLOC,		// Points to memory managed by malloc
	BODY_STORAGE_MMAP,			// Points to a mmap'ed region
	BODY_STORAGE_OBSTACK		// Managed by c->ob obstack
};

enum write_complete_action {
	WRITE_COMPLETE_CLOSE,		// Close the connection when the io completes
	WRITE_COMPLETE_IGNORE
};

enum write_source_type {
	WRITE_SOURCE_BUF
};

struct write_source_buf {
	const unsigned char*	buf;
	size_t					len;
	size_t					written;
};

//typedef void (write_job_free_cb)(struct write_job* job);
typedef void (write_job_free_cb)(void* job);

struct write_job {
	struct dlist_elem			dl;
	enum write_complete_action	action;
	struct ev_loop*				notify_loop;
	struct ev_async*			notify_w;	// If not NULL, this will get ev_async_send'ed when the io completes or fails
	enum write_source_type		source;
	struct obstack*				ob;
	union {
		struct write_source_buf	buf;	// WRITE_SOURCE_BUF
	} src;
	write_job_free_cb*			free_cb;
};

#include "http_headers.h"
#include "msg.h"
#include "report.h"
//#include "inline.h"

void lowercase(unsigned char* str);

// TODO resolve these circular dependencies of struct con_state and these declarations
//void mtagpool_clear(struct mtagpool* mtp, struct con_state* c);
//void new_header_other(struct con_state* c, const unsigned char* field_name_str, int field_name_str_len, const unsigned char* field_value, int field_value_len);
//void new_header_str(struct con_state* c, enum hdr field_name, const unsigned char* field_value, int field_value_len);
//int push_te(struct con_state* c, enum te_types type);
//int push_te_accept(struct con_state* c, const unsigned char* r1, const unsigned char* r2, enum te_types type);
uint64_t con_ts(struct con_state* c);	// Number of nanoseconds since accept

static inline void mtagpool_clear(struct mtagpool* mtp, struct con_state* c) //<<<
{
	obstack_free(mtp->ob, mtp->start);
	mtp->start = obstack_alloc(mtp->ob, 1);
	/*!mtags:re2c:http format = "\tc->@@{tag} = NULL;\n"; */
}

//>>>
static inline void new_header_other(struct con_state* c, const unsigned char* field_name_str, int field_name_str_len, const unsigned char* field_value, int field_value_len) //<<<
{
	struct header*	hdr = new_header(c->ob);

	hdr->field_name			= HDR_OTHER;
	hdr->field_name_str		= obstack_copy0(c->ob, field_name_str, field_name_str_len);
	hdr->field_name_str_len	= field_name_str_len;
	hdr->field_value.str	= obstack_copy0(c->ob, field_value, field_value_len);

	lowercase(hdr->field_name_str);

	append_header(&c->headers, hdr);
}

//>>>
static inline void new_header_str(struct con_state* c, enum hdr field_name, const unsigned char* field_value, int field_value_len) //<<<
{
	struct header*	hdr = new_header(c->ob);

	hdr->field_name			= field_name;
	hdr->field_value.str	= obstack_copy0(c->ob, field_value, field_value_len);

	append_header(&c->headers, hdr);
}

//>>>
static inline int push_te(struct con_state* c, enum te_types type) //<<<
{
	struct header*	h;

	/* Reject duplicates */
	for (h = c->headers.first[HDR_TRANSFER_ENCODING]; h; h = h->type_next)
		if (h->field_value.integer == type) return 1;

	h = new_header(c->ob);
	h->field_name = HDR_TRANSFER_ENCODING;
	h->field_value.integer = type;
	append_header(&c->headers, h);

	return 0;
}

//>>>
static inline int push_te_accept(struct con_state* c, const unsigned char* r1, const unsigned char* r2, enum te_types type) //<<<
{
	struct header*		h;
	struct te_accept*	te;
	float				rank = 0;

	/* Reject duplicates */
	for (h = c->headers.first[HDR_TE]; h; h = h->type_next) {
		struct te_accept*	tmp_te = h->field_value.ptr;
		if (tmp_te->type == type) return 1;
	}

	if (r1 && r2) {
		const unsigned char* d = NULL;

		for (d = r1; d<r2 && *d != '.'; d++) {
			rank *= 10.;
			rank += *d;
		}

		if (*d == '.') {
			float	factor = .1;

			for (d++; d<r2; d++) {
				rank += *d * factor;
				factor *= .1;
			}
		}

		if (rank == 0.0) return 0;	/* Rank of 0 means "not acceptible" - ie. equivalent to not listing this type */
	} else {
		rank = 1.0;
	}

	h = new_header(c->ob);
	h->field_name = HDR_TE;
	h->field_value.ptr = te = obstack_alloc(c->ob, sizeof *te);
	te->rank = rank;
	append_header(&c->headers, h);

	return 0;
}

//>>>

// Utils internal API
//uint64_t nanoseconds_process_cpu();
extern thread_local uint64_t		t_overhead_compensation;
#define nanoseconds_process_cpu()	(__rdtsc() - t_overhead_compensation)
uint64_t nanoseconds_since(uint64_t datum);
long perf_event_open(struct perf_event_attr* hw_event, pid_t pid, int cpu, int group_fd, unsigned long flags);

struct log {
	struct log*	next;
	uint64_t	cycles;
	uint64_t	last_log;
	char*		msg;
	int			len;
};

#if 0
#define ts_log(c, fmt, ...) \
	do { \
		struct con_state* cl = (c); \
		double delta = nanoseconds_since(cl->accept_time) / 1e3; \
		double last_delta = delta - c->last_log; \
		c->last_log = delta; \
		if (obstack_room(c->logs) < 256) { \
			obstack_blank(c->logs, 256); \
		} \
		const int room = obstack_room(c->logs); \
		const int size = snprintf(obstack_base(c->logs) + obstack_object_size(c->logs), room, "[%10.3f kc, %10.3f kc] " fmt "\n", delta, last_delta, __VA_ARGS__); \
		obstack_blank_fast(c->logs, size < room ? size : room-1); /* -1: discard the \0 */ \
		if (size >= room) {obstack_grow(c->logs, "<...>\n", 6);} \
	} while(0)
#else
#define ts_log(c, fmt, ...) \
	do { \
		const uint64_t now = nanoseconds_process_cpu(); \
		struct log*	l = obstack_alloc(c->logs, sizeof *l); \
		l->next = NULL; l->cycles = now; l->last_log = c->last_log; \
		c->last_log = now; \
		if (obstack_room(c->logs) < 256) obstack_blank(c->logs, 256); \
		const int room = obstack_room(c->logs); \
		const int size = snprintf(obstack_base(c->logs), room, fmt, __VA_ARGS__); \
		const int wrote = size < room ? size : room-1; \
		obstack_blank_fast(c->logs, wrote); \
		/*obstack_blank_fast(c->logs, wrote - room); */ \
		if (size >= room) {obstack_grow(c->logs, "<...>\n", 6);} \
		l->len = obstack_object_size(c->logs); \
		l->msg = obstack_finish(c->logs); \
		if (c->logs_tail) { \
			c->logs_tail->next = l; \
			c->logs_tail = l; \
		} else { \
			c->logs_head = c->logs_tail = l; \
		} \
		t_overhead_compensation += nanoseconds_process_cpu() - now;	/* Compensate for logging */ \
	} while(0)
#endif

void ts_puts(struct con_state* c, char*const str, int len);

#define ts_log_output(c) \
	do { \
		struct log*	l = c->logs_head; \
		while (l) { \
			const double delta = (l->cycles - c->accept_time) / 1e3; \
			const double last_delta = (l->cycles - l->last_log) / 1e3; \
			printf("[%10.3f kc, %10.3f kc] %.*s\n", delta, last_delta, l->len, l->msg); \
			l = l->next; \
		} \
		fflush(stdout); \
		obstack_free(c->logs, c->logs_head); \
	} while(0)

#endif

// vim: ft=c foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4
