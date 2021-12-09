#include <evhttpInt.h>
#include <asm/unistd.h>

extern thread_local uint64_t		t_overhead;
extern thread_local uint64_t		t_overhead_compensation;

void lowercase(unsigned char* str) //<<<
{
	unsigned char*	p = NULL;

	for (p=str; *p; p++)
		if (*p >= 'A' && *p <= 'Z')
			*p |= 1<<5;		// Lowercase
}

//>>>
#if 0
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
inline uint64_t nanoseconds_process_cpu() // Number of nanoseconds our process has spent <<<
{
#if 0
	struct timespec now;
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &now);
	return (uint64_t)(now.tv_sec)*1000000000ULL + now.tv_nsec;
#elseif 0
	uint64_t	cycles;
	read(t_cpu_cycles_fd, &cycles, sizeof(long long));
	t_overhead_compensation += t_overhead;
	return cycles - t_overhead_compensation;
#else
	return __rdtsc();
#endif
}
#endif

//>>>
#pragma GCC diagnostic pop
uint64_t nanoseconds_since(uint64_t datum) // Number of nanoseconds since datum <<<
{
	return nanoseconds_process_cpu() - datum;
}

//>>>
long perf_event_open(struct perf_event_attr* hw_event, pid_t pid, int cpu, int group_fd, unsigned long flags) //<<<
{
	return syscall (__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

//>>>

void ts_puts(struct evhttp_con* c, char*const str, int len)
{
	const uint64_t	now = nanoseconds_process_cpu();
	struct log*		l = obstack_alloc(c->logs, sizeof *l);

	l->next = NULL;
	l->cycles = now;
	l->last_log = c->last_log;
	c->last_log = now;
	l->msg = obstack_copy(c->logs, str, len);
	l->len = len;
	if (c->logs_tail) {
		c->logs_tail->next = l;
		c->logs_tail = l;
	} else {
		c->logs_tail = c->logs_head = l;
	}
	t_overhead_compensation += nanoseconds_process_cpu() - now;	// Compensate for logging

#if 0
	const uint64_t log_before = nanoseconds_process_cpu();
		struct evhttp_con* cl = (c); \
		const uint64_t cycles = nanoseconds_since(cl->accept_time); \
		double delta = cycles / 1e3; \
		double last_delta = delta - cl->last_log; \
		uint64_t last_delta_int = last_delta*1000;
		cl->last_log = delta; \
		const int msb = 64-__builtin_clzl(last_delta_int);
		const int maxlen = msb/3+1; \
		//uint64_t	t = 4294967296ULL;
		uint64_t	t = 1ULL<<0;
		//fprintf(stderr, "last_delta_int: %ld, msb: %d, maxlen: %d, t: %ld: %d\n", last_delta_int, msb, maxlen, t, 64-__builtin_clzl(t));
		if (obstack_room(cl->logs) < maxlen+1+len) obstack_blank(cl->logs, maxlen+1+len); \
		char* base = obstack_base(cl->logs);
		char* start = base + obstack_object_size(cl->logs);
		char* p = start + maxlen; \
		uint64_t acc = last_delta_int; \
		while (acc) { \
			*p-- = '0' + (acc % 10); \
			acc /= 10; \
		} \
		while (p >= start) {
			*p-- = '_';
		}
		obstack_blank_fast(cl->logs, maxlen); \
		obstack_1grow_fast(cl->logs, ':'); \
		obstack_grow(cl->logs, str, len); \
		const uint64_t log_after = nanoseconds_process_cpu();
		//fprintf(stderr, "logs size: %d, log ns: %ld\n%.*s", obstack_object_size(cl->logs), log_after-log_before, obstack_object_size(cl->logs), obstack_base(cl->logs));
#endif
}
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
// vim: foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4
