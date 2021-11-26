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
	int					ev_pipe_w;
	struct ev_io		accept_watcher;
	struct listensock*	next;
};

enum ev_type {
	EV_PIPE_NEWCON,
	EV_PIPE_REQ,
	EV_PIPE_CONCLOSED
};

struct ev_pipe_event {
	enum ev_type	type;
	void*			data;
};

enum con_status {
	CON_STATUS_WAITING,
	CON_STATUS_OVERFLOW,
	CON_STATUS_ERROR,
	CON_STATUS_BODY,
	CON_STATUS_BODY_DONE
};

enum con_role {
	CON_ROLE_SERVER,
	CON_ROLE_CLIENT
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

enum aio_action {
	AIO_DONE_CLOSE,		// Close the connection when the io completes
	AIO_DONE_IGNORE
};

struct aio_done_action {
	struct ev_io*		con_watch;
	enum aio_action		action;
	struct ev_async*	notify_w;	// If not NULL, this will get ev_async_send'ed when the io completes or fails
};

#include "http_headers.h"
#include "msg.h"
#include "report.h"


// TODO resolve these circular dependencies of struct con_state and these declarations
void mtagpool_clear(struct mtagpool* mtp, struct con_state* c);
void new_header_other(struct con_state* c, const unsigned char* field_name_str, int field_name_str_len, const unsigned char* field_value, int field_value_len);
void new_header_str(struct con_state* c, enum hdr field_name, const unsigned char* field_value, int field_value_len);
int push_te(struct con_state* c, enum te_types type);
int push_te_accept(struct con_state* c, const unsigned char* r1, const unsigned char* r2, enum te_types type);
uint64_t con_ts(struct con_state* c);	// Number of nanoseconds since accept

// Utils internal API
void lowercase(unsigned char* str);
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
	} while(0)

#endif
