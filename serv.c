#include "evhttpInt.h"

/*
static void my_obstack_alloc_failed()
{
	fprintf(stderr, "Failed to allocate memory for obstack\n");
	exit(EXIT_FAILURE);
}
*/

struct timespec before;
double empty = 0.0;

static struct ev_loop*		io_thread_loop = NULL;
static struct ev_async		io_thread_wakeup;

struct msg_queue {
	struct dlist_elem		dl;		// Must be first
	int						evfd;
	pthread_mutex_t			msgs_mutex;
	struct dlist			msgs;
	evhttp_msg_handler*		cb;
};

pthread_mutex_t		listensock_mutex = PTHREAD_MUTEX_INITIALIZER;

struct listensock_queue g_listensock_queue = {
	.head = NULL,
	.tail = NULL
};

struct listensock_queue g_listensock_active = {
	.head = NULL,
	.tail = NULL
};

pthread_mutex_t		autoinit_mutex = PTHREAD_MUTEX_INITIALIZER;
static int			autoinit_done = 0;

pthread_mutex_t		write_message_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
struct dlist g_write_message_queue = {
	.head = NULL,
	.tail = NULL
};

//thread_local struct perf_event_attr	t_pe = {0};
thread_local int		t_cpu_cycles_fd;
thread_local uint64_t	t_overhead = 0;
thread_local uint64_t	t_overhead_compensation = 0;

void con_io_cb(struct ev_loop* loop, struct ev_io* _w, int revents);

void post_listensock(struct listensock* sock) //<<<
{
	pthread_mutex_lock(&listensock_mutex);
	if (g_listensock_queue.tail) {
		g_listensock_queue.tail->next = sock;
		sock->next = NULL;
	} else {
		g_listensock_queue.head = g_listensock_queue.tail = sock;
		sock->next = NULL;
	}
	pthread_mutex_unlock(&listensock_mutex);

	ev_async_send(io_thread_loop, &io_thread_wakeup);
}

//>>>
void modify_io_evmask(struct ev_loop* loop, struct ev_io* w, int set, int clear) //<<<
{
	const int evmask	= (w->events | set) & ~clear;

	ev_io_stop(loop, w);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wparentheses"
	ev_io_modify(w, evmask);
#pragma GCC diagnostic pop
	if (evmask & (EV_READ|EV_WRITE)) {
		ev_io_start(loop, w);
	}
}

//>>>
static void io_thread_wakeup_cb(struct ev_loop* loop, struct ev_async* w, int revents) //<<<
{
	struct listensock*	sock = NULL;

	// Receive and start listen sock accept watches <<<
	if (g_listensock_queue.head) {
		pthread_mutex_lock(&listensock_mutex);
		sock = g_listensock_queue.head;
		while (sock) {
			ev_io_start(io_thread_loop, &sock->accept_watcher);
			sock = sock->next;
		}
		if (g_listensock_active.tail) {
			g_listensock_active.tail->next = g_listensock_queue.head;
			g_listensock_active.tail = g_listensock_queue.tail;
		} else {
			g_listensock_active.head = g_listensock_queue.head;
			g_listensock_active.tail = g_listensock_queue.tail;
		}
		g_listensock_queue.head = g_listensock_queue.tail = NULL;
		pthread_mutex_unlock(&listensock_mutex);
	}
	// Receive and start listen sock accept watches >>>

	// Receive and start queued write jobs <<<
	if (g_write_message_queue.head) {
		pthread_mutex_lock(&write_message_queue_mutex);
		struct dlist	write_queue = g_write_message_queue;
		g_write_message_queue.head = g_write_message_queue.tail = NULL;
		pthread_mutex_unlock(&write_message_queue_mutex);

		struct con_watch*	w;
		while ((w = dlist_pop_head(&write_queue))) {
			modify_io_evmask(io_thread_loop, (struct ev_io*)w, EV_WRITE, 0);
			con_io_cb(loop, (struct ev_io*)w, EV_WRITE);
		}
	}
	// Receive and start queued write jobs >>>
}

//>>>
void close_t_cpu_cycles_fd(void* cdata) //<<<
{
	const pthread_t	tid = pthread_self();
	//fprintf(stderr, "Closing t_cpu_cycles_fd in %s (%p)\n", name(tid), tid);
	fprintf(stderr, "Closing t_cpu_cycles_fd in %ld\n", tid);
	close(t_cpu_cycles_fd);
}

//>>>
void free_con_state(struct con_watch* w) //<<<
{
	struct evhttp_con*	c = w->w.data;

	if (c->body_fd != -1) {
		close(c->body_fd);
		c->body_fd = -1;
	}
	if (c->body_storage == BODY_STORAGE_MMAP) {
		if (c->body != MAP_FAILED) {
			if (munmap(c->body, c->body_avail)) {
				perror("Error munmapping body tmpfile");
			}
			c->body = NULL;
		}
		c->body_storage = BODY_STORAGE_NONE;
	}
	mtagpool_free(&c->mtp);
	{ // Cancel any uncompleted write jobs
		struct write_job*	job;
		while ((job = dlist_pop_head(&c->write_jobs))) {
			// TODO: notify the failure (cancellation) of this write job somehow?
			if (job->free_cb)
				job->free_cb(job);
		}
	}
	ts_log_output(c);
	obstack_pool_release(c->logs);
	obstack_pool_release(c->ob);
	w->w.data = NULL;
}

//>>>
static void close_con(struct con_watch* w) //<<<
{
	close(w->w.fd);
	ev_io_stop(w->loop, (struct ev_io*)w);
	free_con_state(w);
	free(w);
	w = NULL;
}

//>>>
static void* thread_start(void* cdata) //<<<
{
	struct perf_event_attr	pe = {0};
	int						evfd = *(int*)cdata;

	io_thread_loop = ev_loop_new(EVFLAG_AUTO);
	if (io_thread_loop == NULL) {
		fprintf(stderr, "Could not initialize thread loop\n");
		goto failed;
	}

	ev_async_init(&io_thread_wakeup, io_thread_wakeup_cb);
	ev_async_start(io_thread_loop, &io_thread_wakeup);

	pe.type = PERF_TYPE_HARDWARE;
	pe.size = sizeof pe;
	pe.config = PERF_COUNT_HW_CPU_CYCLES;
	//pe.config = PERF_COUNT_HW_INSTRUCTIONS;
	pe.disabled = 1;
	pe.exclude_kernel = 0;
	pe.exclude_hv = 1;

	// Need to set /proc/sys/kernel/perf_event_paranoid to 0 or 1 to use without root
	t_cpu_cycles_fd = perf_event_open(&pe, 0, -1, -1, 0);
	if (t_cpu_cycles_fd == -1) {
		perror("Could not open t_cpu_cycles_fd");
		goto failed;
	}

	pthread_cleanup_push(close_t_cpu_cycles_fd, NULL);
	ioctl(t_cpu_cycles_fd, PERF_EVENT_IOC_RESET, 0);
	ioctl(t_cpu_cycles_fd, PERF_EVENT_IOC_ENABLE, 0);

	const uint64_t	cycles_before = nanoseconds_process_cpu();
	printf("Measuring instruction count for this printf\n");
	const uint64_t	cycles_after = nanoseconds_process_cpu();

	//ioctl(t_cpu_cycles_fd, PERF_EVENT_IOC_DISABLE, 0);
	long long count;
	ssize_t ignored = read(t_cpu_cycles_fd, &count, sizeof(long long));
	if (ignored) {}
	//ioctl(t_cpu_cycles_fd, PERF_EVENT_IOC_ENABLE, 0);

	const uint64_t	cycles_before2 = nanoseconds_process_cpu();
	//read(t_cpu_cycles_fd, &count, sizeof(long long));
	//const uint64_t	cycles_before2 = count;
	printf("Measuring instruction count for this printf\n");
	//read(t_cpu_cycles_fd, &count, sizeof(long long));
	const uint64_t	cycles_after2 = nanoseconds_process_cpu();
	//const uint64_t	cycles_after2 = count;

	const uint64_t	cycles_before3 = nanoseconds_process_cpu();
	printf("printf cycles: %lld, %ld, %ld\n", count, cycles_after - cycles_before, cycles_after2 - cycles_before2);
	const uint64_t	cycles_after3 = nanoseconds_process_cpu();
	printf("printf with conversions cycles: %ld\n", cycles_after3 - cycles_before3);

	const uint64_t	cycles_before4 = nanoseconds_process_cpu();
	const int		it = 10000;
	int	n = it;
	__asm__ (
			"1:;\n"
			"sub $1, %[n];\n"
			"jne 1b;\n"
			: [n] "+r" (n)
			:
			:
	);
	const uint64_t	cycles_after4 = nanoseconds_process_cpu();
	printf("asm %d cycles: %ld\n", it, cycles_after4 - cycles_before4);

	const uint64_t	empty1 = nanoseconds_process_cpu();
	const uint64_t	empty2 = nanoseconds_process_cpu();
	t_overhead = empty2-empty1;
	printf("nanoseconds_process_cpu overhead: %ld\n", empty2 - empty1);

	const uint64_t	empty3 = nanoseconds_process_cpu();
	const uint64_t	empty4 = nanoseconds_process_cpu();
	printf("nanoseconds_process_cpu overhead compensated: %ld\n", empty4 - empty3);

	/*
	delta = after.tv_sec - before.tv_sec + (after.tv_nsec - before.tv_nsec)/1e9 - empty;
	fprintf(stderr, "io_thread start latency: %.1f microseconds\n", delta*1e6);
	*/

	printf("In thread %ld\n", pthread_self());

	// Signal readiness
	if (-1 == write(evfd, &(uint64_t){0+256}, sizeof(uint64_t))) {
		perror("Write to evfd to signal io_thread readiness");
		// TODO: what?
		goto failed;
	}

	ev_run(io_thread_loop, 0);
	ev_loop_destroy(io_thread_loop);

	pthread_cleanup_pop(1);
	return NULL;

failed:
	if (-1 == write(evfd, &(uint64_t){-1+256}, sizeof(uint64_t))) {
		perror("Write to evfd to signal io_thread startup failure");
		// TODO: what?
		goto failed;
	}
	pthread_exit(NULL);
}

//>>>
#if 0
void ev_pipe_cb(struct ev_loop* loop, struct ev_io* w, int revents) //<<<
{
	struct ev_pipe_event	pipe_ev;
	ssize_t					got = read(w->fd, &pipe_ev, sizeof pipe_ev);

	if (got == -1) {
		switch (errno) {
			case EAGAIN:
#if EAGAIN != EWOULDBLOCK
			case EWOULDBLOCK:
#endif
				/*
				 * Since we're writing less than PIPE_BUF bytes, EAGAIN or EWOULDBLOCK
				 * should only occur for the spurious wakeup case, so no partial read should
				 * have happened.
				 */
				return;
			default:
				perror("Could not read from ev_pipe");
				exit(EXIT_FAILURE);
		}
	}

	printf("Got pipe_ev read in thread %ld\n", pthread_self());
	switch (pipe_ev.type) {
		case EV_PIPE_NEWCON:
			printf("New connection event\n");
			break;
		case EV_PIPE_REQ:
			printf("New request\n");
			break;
		case EV_PIPE_CONCLOSED:
			printf("New request\n");
			break;
		default:
			fprintf(stderr, "Unhandled pipe_ev.type: %d\n", pipe_ev.type);
			break;
	}
}

//>>>
#endif
#if 0
void respond(struct ev_loop* loop, struct ev_io* w, int status, struct headers* headers, struct write_source* body, enum write_complete_action action) //<<<
{
	struct evhttp_con*		c = w->data;
	struct write_job*		headers_job = obstack_alloc(c->ob, sizeof *headers_job);
	struct write_job*		job = obstack_alloc(c->ob, sizeof *job);

	headers_job->write_complete_action = WRITE_COMPLETE_IGNORE;

	job->write_complete_action = action;
	job->notify_w = NULL;
	job->source = *body;

	dlist_append(&c->write_jobs, job);

	con_io_cb(loop, w, EV_WRITE);
}

//>>>
#endif
void release_write_job_obstack(void* jobPtr) //<<<
{
	struct write_job*	job = jobPtr;

	if (job->ob) {
		obstack_pool_release(job->ob);
		job->ob = NULL;
	}
}

//>>>
struct evhttp_con* init_con_state(enum con_role role) //<<<
{
	uint64_t			now = nanoseconds_process_cpu();
	struct obstack*		ob = obstack_pool_get(OBSTACK_POOL_SMALL);
	struct evhttp_con*	c = obstack_alloc(ob, sizeof *c);

	c->ob				= ob;
	c->logs				= obstack_pool_get(OBSTACK_POOL_SMALL);
	c->logs_head		= NULL;
	c->logs_tail		= NULL;
	c->last_log			= now;
	init_msg_buffer(c);
	c->accept_time		= now;
	c->state			= -1;
	c->status			= CON_STATUS_WAITING;
	c->status_code[0]	= 0;
	c->status_numeric	= 200;
	c->role				= role;
	c->method			= EVHTTP_METHOD_UNSPECIFIED;
	c->custom_method	= NULL;
	c->http_ver			= NULL;
	c->connectionflags	= 0;
	c->body_len			= BODY_LEN_NOTSET;
	c->body_size		= 0;
	c->body_avail		= 0;
	c->body				= NULL;
	c->body_storage		= BODY_STORAGE_NONE;
	c->body_fd			= -1;
	c->chunk_remain		= 0;
	c->write_jobs.head	= NULL;
	c->write_jobs.tail	= NULL;

	init_headers(&c->headers);
	init_headers(&c->out_headers);

	return c;
}

//>>>
void con_io_cb(struct ev_loop* loop, struct ev_io* _w, int revents) //<<<
{
	struct con_watch*	w = (struct con_watch*)_w;
	struct evhttp_con*	c = w->w.data;

	if (c == NULL) {
		w->w.data = c = init_con_state(w->role);
		c->w = w;
	}

	ts_puts(c, "con_io_cb", sizeof("con_io_cb")-1);
	if (revents & EV_WRITE) { // Write any waiting data we can <<<
		struct write_job*	job;
		while ((job = dlist_head(&c->write_jobs))) {
			switch (job->source) {
				case WRITE_SOURCE_BUF: //<<<
					{
						struct write_source_buf*	srcbuf = &job->src.buf;
						const ssize_t remain = srcbuf->len - srcbuf->written;
						const uint64_t send1 = nanoseconds_process_cpu();
						const ssize_t wrote = send(w->w.fd, srcbuf->buf + srcbuf->written, remain, MSG_DONTWAIT | MSG_NOSIGNAL | (job->dl.next ? MSG_MORE : 0));
						//const ssize_t wrote = send(w->w.fd, srcbuf->buf + srcbuf->written, remain, MSG_DONTWAIT | MSG_NOSIGNAL);
						const uint64_t send2 = nanoseconds_process_cpu();

						if (wrote == -1) {
							switch (errno) {
#if EAGAIN != EWOULDBLOCK
								case EWOULDBLOCK:
#endif
								case EAGAIN:
									if (!(w->w.events & EV_WRITE))
										modify_io_evmask(loop, (struct ev_io*)w, EV_WRITE, 0);
									goto read;
									return;

								default:
									perror("Error writing to fd");
									goto close;
							}
						} else {
							srcbuf->written += wrote;
							ts_log(c, "Wrote %ld bytes (%ld remain): %ld cycles", wrote, srcbuf->len - srcbuf->written, send2-send1);
							if (wrote < remain) {
								if (!(w->w.events & EV_WRITE))
									modify_io_evmask(loop, (struct ev_io*)w, EV_WRITE, 0);
								goto read;
							} else {
								//ts_puts(c, "Completed write job", sizeof("Completed write job")-1);
								// Completed this write job
								dlist_pop_head(&c->write_jobs);

								if (job->notify_loop && job->notify_w)
									ev_async_send(job->notify_loop, job->notify_w);


								const enum write_complete_action	action	= job->action;

								if (job->free_cb)
									job->free_cb(job);

								switch (action) {
									case WRITE_COMPLETE_IGNORE:	break;
									case WRITE_COMPLETE_CLOSE:	goto close;
								}
								continue;
							}
						}
					}
					//>>>
					break;

				default:
					ts_puts(c, "Invalid write source", sizeof("Invalid write source")-1);
					goto close;
					break;
			}
		}
	}

	// Write any waiting data we can >>>

read:
	if (!(revents & EV_READ)) return;
	// Read any waiting data <<<
loop:
	{
		const size_t		shift = c->tok - c->buf;
		const size_t		free = c->buf_size - (c->lim - c->tok);

		if (c->status == CON_STATUS_BODY && c->body_len != BODY_LEN_CHUNKED) { // Read the body (not chunked) <<<
			ssize_t		got;
			ssize_t		remain;

			// Calculate (or estimate) how much we still need to read <<<
			switch (c->body_len) {
				case BODY_LEN_CONTENT_LENGTH:
					remain = c->headers.first[EVHTTP_HDR_CONTENT_LENGTH]->field_value.integer - c->body_size;
					break;
				case BODY_LEN_EOF:
					remain = c->body_avail < 4096 ? 1048576 : c->body_avail;		// Just something large
					break;
				default:
					fprintf(stderr, "Invalid c->body_len: %d\n", c->body_len);
					goto close_500;
			}

			// Calculate (or estimate) how much we still need to read >>>
			// Grow the body allocation if needed <<<
			if (c->body_size + remain < c->body_avail) {
				switch (c->body_storage) {
					case BODY_STORAGE_OBSTACK:
						obstack_blank(c->ob, remain);
						c->body = obstack_base(c->ob);
						c->body_avail = obstack_object_size(c->ob) + obstack_room(c->ob);
						break;

					case BODY_STORAGE_MMAP:
						{
							const size_t	new_size = c->body_size + remain;

							if (-1 == ftruncate(c->body_fd, new_size)) {
								perror("Error calling ftruncate to expand the body tmpfile");
								goto close_500;
							}

							void*	new = mremap(c->body, c->body_avail, new_size, MREMAP_MAYMOVE);

							if (new == MAP_FAILED) {
								perror("Error growing body mmap");
								goto close_500;
							}
							c->body = new;
							c->body_avail = new_size;
						}
						break;

					default:
						fprintf(stderr, "Unhandled body_storage: %d\n", c->body_storage);
						goto close_500;
				}
			}

			// Grow the body allocation if needed >>>
			// Read more body bytes <<<
			got = read(w->w.fd, c->body + c->body_size, remain);
			if (got == -1) {
				switch (errno) {
#if EAGAIN != EWOULDBLOCK
					case EWOULDBLOCK:
#endif
					case EAGAIN:
						return;

					default:
						perror("Error reading from fd");
						goto close;
				}
			} else if (got == 0) {
				if (c->body_len == BODY_LEN_EOF) {
					goto message_complete;
				}
				goto close_400;
			}
			c->body_size += got;

			// Read more body bytes >>>
			//>>>
		} else { // Parse the headers or chunked body <<<
			if (free < 1) {
				/* Input token too long for receive buffer */
				// TODO: switch buf to heap allocated memory instead, or realloc to grow it if it is already dynamic
				fprintf(stderr, "Token too long for receive buffer: %ld\n", c->buf_size);
				goto close;
			}

			uint64_t	shift1 = nanoseconds_process_cpu();
			if (shift) {
				//report("shifting to", c->tok);
				shift_msg_buffer(c, shift);
			}
			uint64_t	shift2 = nanoseconds_process_cpu();

			const uint64_t	read1 = nanoseconds_process_cpu();
			const ssize_t got = read(w->w.fd, c->lim, c->buf_size - (c->lim - c->buf));
			const uint64_t	read2 = nanoseconds_process_cpu();
			if (got == -1) {
				switch (errno) {
#if EAGAIN != EWOULDBLOCK
					case EWOULDBLOCK:
#endif
					case EAGAIN:
						if (c->cur < c->lim) break;	// May not have read any more, but we have some already waiting
						ts_puts(c, "EAGAIN", sizeof("EAGAIN")-1);
						return;
					default:
						perror("Error reading from con fd");
						goto close;
				}
			} else if (got == 0) {
				printf("Connection socket closed\n");
				goto close_400;
			}

			c->lim += got;
			c->lim[0] = 0;	// Append sentinel

			ts_log(c, "read: %ld bytes, %ld cycles, shift: %ld", got, read2-read1, shift2-shift1);
			const unsigned char*	bbefore = c->cur;
			uint64_t parse1 = nanoseconds_process_cpu();
			c->status = parse_http_message(c);
			uint64_t parse_elapsed = nanoseconds_process_cpu() - parse1;
			const int bytecount = c->cur - bbefore;
			ts_log(c, "Parse %d byte chunk: %ld cycles: %.2f cycles/byte", bytecount, parse_elapsed, (double)(parse_elapsed)/bytecount);
			switch (c->status) {
				case CON_STATUS_WAITING:
					ts_log(c, "%s", "parse_con_req returned CON_STATUS_WAITING");
					// Loop back around in case the fd has more to give us
					goto loop;;

				case CON_STATUS_BODY:
					/* Instead of incrementing c->header_count as we add them, we could do it here: */
					// c->header_count = obstack_size(&c->headers_storage) / sizeof(struct header);
					ts_log(c, "%s", "Got headers, read body");

					// Determine message body length as per RFC7230 section 3.3.3 <<<
					if (
							(c->role == CON_ROLE_CLIENT && c->method == EVHTTP_METHOD_HEAD) ||
							(c->role == CON_ROLE_CLIENT && c->method == EVHTTP_METHOD_CONNECT) ||
							(c->status_numeric >= 100 && c->status_numeric <= 199) ||
							c->status_numeric == 204 ||
							c->status_numeric == 304
					) {
						// No body, regardless of any header fields that might indicate a length
						c->body_len = BODY_LEN_NONE;
					} else if (c->headers.first[EVHTTP_HDR_TRANSFER_ENCODING]) { // Transfer-Encoding present
						if (c->headers.first[EVHTTP_HDR_CONTENT_LENGTH]) {
							// MUST strip content_length if it was present
							remove_header(&c->headers, c->headers.first[EVHTTP_HDR_CONTENT_LENGTH]);
						}

						if (last_header(&c->headers, EVHTTP_HDR_TRANSFER_ENCODING)->field_value.integer == TE_CHUNKED) {
							// Message length is determined by chunked transfer coding
							c->body_len = BODY_LEN_CHUNKED;
						} else {
							if (c->role == CON_ROLE_CLIENT) {
								// Message length is everything until the server closes the connection
								c->body_len = BODY_LEN_EOF;
							} else {
								// Message length cannot be determined.  MUST reject with 400 Bad Request and close the connection
								goto close_400;
							}
						}
					} else if (c->headers.first[EVHTTP_HDR_CONTENT_LENGTH]) {
						// Content-Length gives the body length
						c->body_len = BODY_LEN_CONTENT_LENGTH;
					} else {
						if (c->role == CON_ROLE_SERVER) {
							// Length is 0
							c->body_len = BODY_LEN_NONE;
						} else {
							// Length is until the server closes the connection
							c->body_len = BODY_LEN_EOF;
						}
					}

					// Determine message body length as per RFC7230 section 3.3.3 >>>
					// Set up for the body read <<<
					const int have = c->lim - c->cur;

					switch (c->body_len) {
						case BODY_LEN_NONE:
							goto message_complete;
						case BODY_LEN_CONTENT_LENGTH:
							{
								const int content_length = c->headers.first[EVHTTP_HDR_CONTENT_LENGTH]->field_value.integer;
								if (content_length == 0)
									goto message_complete;

								if (have >= content_length) {
									// We already have the complete body
									c->body_storage = BODY_STORAGE_BORROWED;
									c->body = c->cur;
									c->body_size = content_length;
									c->cur += content_length;
									c->tok = c->mar = c->cur;
									goto message_complete;
								}

								const int room = obstack_room(c->ob);
								if (room >= content_length) {
									// There is room available on the obstack, move what we have there
									c->body_storage = BODY_STORAGE_OBSTACK;
									obstack_grow(c->ob, c->cur, have);
									c->body = obstack_base(c->ob);
									c->body_avail = have + obstack_room(c->ob);
									c->body_size = have;
								} else {
									// Create a memory mapped unlinked tmpfile
									int		rc;
									c->body_storage = BODY_STORAGE_MMAP;
									c->body_fd = open(".", O_TMPFILE | O_RDWR, S_IRUSR | S_IWUSR);
									rc = ftruncate(c->body_fd, content_length);
									if (rc == -1) {
										perror("Could not expand body tmpfile");
										goto close_500;
									}
									c->body = mmap(NULL, content_length, PROT_READ | PROT_WRITE, MAP_SHARED, c->body_fd, 0);
									if (c->body == MAP_FAILED) {
										perror("Could not mmap body tmpfile");
										goto close_500;
									}
									c->body_avail = content_length;

									memcpy(c->body, c->cur, have);
									c->body_size = have;
									// Keep c->body_fd open in case we want to save this message body to a file later (just link the file)
								}
								c->cur = c->tok = c->mar = c->lim;
							}
							break;
						case BODY_LEN_CHUNKED:
							c->body_storage = BODY_STORAGE_OBSTACK;
							// Leave what remains in buf at c->cur, we'll have to parse the chunked encoding
							// Reset the parser state to decode the chunked encoding
							c->cond = yycchunk;
							c->state = -1;
							c->tok = c->mar = c->cur;
							break;
						case BODY_LEN_EOF:
							c->body_storage = BODY_STORAGE_OBSTACK;
							obstack_grow(c->ob, c->cur, have);
							c->body = obstack_base(c->ob);
							c->body_size = have;
							c->body_avail = have + obstack_room(c->ob);
							c->cur = c->tok = c->mar = c->lim;
							break;
						default:
							fprintf(stderr, "Invalid con_status: %d\n", c->status);
							goto close_500;
					}
					// Set up for the body read >>>

					if (c->body_storage == BODY_STORAGE_OBSTACK) {
						// If we need to grow the obstack while reading the body it
						// is a signal that the body is likely large.  Set the chunk size
						// up from the default 4096 so that we grow in larger increments
						obstack_chunk_size(c->ob) = 1048576;  // TODO: tune this
					}

					goto loop;

				case CON_STATUS_BODY_DONE:
					goto message_complete;

				case CON_STATUS_ERROR:
					fprintf(stderr, "Protocol error\n");
					goto close_400;

				default:
					fprintf(stderr, "Bad con status: %d\n", c->status);
					goto close_500;
			}
		}
		//>>>
	}

	// Read any waiting data >>>

	return;

close:
	close_con(w);
	return;

close_400:
	// Respond with 400 Bad Request and close
	ts_puts(c, "Responding with 400 Bad Request", sizeof("Responding with 400 Bad Request")-1);
	{
		struct obstack*	ob = obstack_pool_get(OBSTACK_POOL_SMALL);
		evhttp_err		err = {NULL, EVHTTP_OK};

		// Assemble body
		obstack_grow(ob, "Bad Request", sizeof("Bad Request")-1);
		const size_t			body_len = obstack_object_size(ob);
		const unsigned char*	body = obstack_finish(ob);

		init_headers(&c->out_headers);
#define ADD_STATIC_HEADER(hdrname, strval) \
		do { \
			struct header*	h = obstack_alloc(ob, sizeof(struct header)); \
			h->field_name = EVHTTP_HDR_OTHER; \
			h->field_name_str = (unsigned char*)hdrname; \
			h->field_name_str_len = sizeof(hdrname)-1; \
			h->field_value.str = (unsigned char*)strval; \
			append_header(&c->out_headers, h); \
		} while(0);

		ADD_STATIC_HEADER("Server",			"evhttp 0.1");
		// TODO: Date, etc
		ADD_STATIC_HEADER("Connection",		"close");
		ADD_STATIC_HEADER("Content-Type",	"text/plain;charset=utf-8");

		struct header*	h = obstack_alloc(ob, sizeof(struct header));
		h->field_name = EVHTTP_HDR_CONTENT_LENGTH;
		h->field_value.integer = body_len;
		append_header(&c->out_headers, h);

		obstack_grow(ob, "HTTP/1.1 400 Bad Request\r\n", sizeof("HTTP/1.1 400 Bad Request\r\n")-1);
		err = serialize_headers(ob, &c->out_headers);
		if (err.msg) {
			ts_log(c, "Error serializing headers: %s", err.msg);
			goto close;
		}

		const size_t			hdrbuf_len = obstack_object_size(ob);
		const unsigned char*	hdrbuf = obstack_finish(ob);
		struct write_job*		write_headers = obstack_alloc(ob, sizeof *write_headers);
		memset(write_headers, 0, sizeof *write_headers);
		write_headers->source = WRITE_SOURCE_BUF;
		write_headers->src.buf.len = hdrbuf_len;
		write_headers->src.buf.buf = hdrbuf;
		write_headers->action = WRITE_COMPLETE_IGNORE;
		dlist_append(&c->write_jobs, write_headers);
		

		struct write_job*		write_body = obstack_alloc(ob, sizeof *write_body);
		memset(write_body, 0, sizeof *write_body);
		write_body->source = WRITE_SOURCE_BUF;
		write_body->src.buf.len = body_len;
		write_body->src.buf.buf = body;
		write_body->action = WRITE_COMPLETE_CLOSE;
		write_body->ob = ob;
		write_body->free_cb = &release_write_job_obstack;
		dlist_append(&c->write_jobs, write_body);

		if (w->w.events & EV_READ)
			modify_io_evmask(loop, (struct ev_io*)w, 0, EV_READ);

		ts_puts(c, "Constucted and queued response", sizeof("Constucted and queued response")-1);
		con_io_cb(loop, (struct ev_io*)w, EV_WRITE);
#undef ADD_STATIC_HEADER
	}
	return;

close_500:
	// TODO: Respond with 500 Bad Request and close
	goto close;

message_complete:
	ts_puts(c, "Message complete", sizeof("Message complete"));
	/*
	// TODO: dispatch callback for message
	struct obstack* ob = obstack_pool_get(OBSTACK_POOL_SMALL);
	const uint64_t	ser1 = nanoseconds_process_cpu();
	if (serialize_headers(ob, &c->headers)) {
		ts_puts(c, "Error serializing headers", sizeof("Error serializing headers"));
	} else {
		const uint64_t	ser2 = nanoseconds_process_cpu();
		const int				hstr_len = obstack_object_size(ob);
		const unsigned char*	hstr = obstack_finish(ob);
		ts_log(c, "Headers: %ld cycles\n%.*s", ser2-ser1, hstr_len, hstr);
		//report("headers", hstr);
	}
	obstack_pool_release(ob); ob = NULL;
	*/
	/*
	pthread_mutex_lock(&w->listener->requests_mutex);
	dlist_append(&w->listener->requests, c);
	pthread_mutex_unlock(&w->listener->requests_mutex);

	ev_async_send(w->listener->requests_loop, &w->listener->requests_ready);
	*/

	// Post this completed message to the thread owning the queue
	const uint64_t	p1 = nanoseconds_process_cpu();
	evhttp_err		err = {NULL, EVHTTP_OK};
	modify_io_evmask(loop, (struct ev_io*)w, 0, EV_READ|EV_WRITE);
	pthread_mutex_lock(&w->listener->msg_queue->msgs_mutex);
	if (w->listener->msg_queue->cb == NULL) {
		// The handler (listener / client) has shut down, nowhere to send this message
		err = ERR("Receiver went away", EVHTTP_ERR_SEQUENCE);
	}
	if (err.msg == NULL)
		dlist_append(&w->listener->msg_queue->msgs, w);
	pthread_mutex_unlock(&w->listener->msg_queue->msgs_mutex);

	if (err.msg && c->role == CON_ROLE_SERVER) {
		// TODO: send a 500 error for this request and close
		evhttp_con_set_status(c, 500);
		evhttp_con_set_body(c, "Server is shutting down");
		evhttp_con_set_header(c, EVHTTP_HDR_CONNECTION, .value="close");
		c->connectionflags |= CON_CLOSE;
		evhttp_con_respond(c);
		goto close;
	} else {
		const ssize_t wrote = write(w->listener->msg_queue->evfd, &(uint64_t){1}, sizeof(uint64_t));
		if (-1 == wrote) {
			perror("Writing to msg_queue notify eventfd");
			// TODO: what?
		}
	}

	c = NULL; w = NULL; // ownership transferred to receiving thread
	const uint64_t	p2 = nanoseconds_process_cpu();
	printf("Posted complete message to msg_queue owner thread: %ld cycles\n", p2-p1);

	return;
}

//>>>
void accept_cb(struct ev_loop* loop, struct ev_io* _w, int revents) //<<<
{
	//uint64_t					accept_start = nanoseconds_process_cpu();
	struct listensock*			w = (struct listensock*)_w;
	int							con_fd;
	struct sockaddr_storage		con_addr;
	struct con_watch*			con_watch = NULL;
	socklen_t					addrlen = sizeof con_addr;

	con_fd = accept4(w->accept_watcher.fd, (struct sockaddr*)&con_addr, &addrlen, SOCK_NONBLOCK | SOCK_CLOEXEC);
	if (con_fd == -1) {
		perror("Could not accept new connection");
		exit(EXIT_FAILURE);
	}

	con_watch = malloc(sizeof *con_watch);
	con_watch->listener = w;
	con_watch->role = CON_ROLE_SERVER;
	con_watch->loop = loop;
	//ev_io_init((struct ev_io*)con_watch, con_io_cb, con_fd, EV_READ);
	ev_init((struct ev_io*)con_watch, con_io_cb);
	ev_io_set((struct ev_io*)con_watch, con_fd, EV_READ);
	con_watch->w.data = NULL;
	ev_io_start(con_watch->loop, (struct ev_io*)con_watch);
	con_io_cb(con_watch->loop, (struct ev_io*)con_watch, EV_READ);	// Optimistically assume there is already data for us, rather than waiting for the readable event
}

//>>>
evhttp_err start_listen(struct msg_queue* q, const char* node, const char* service) //<<<
{
	struct addrinfo		hints;
	struct addrinfo*	res = NULL;
	struct addrinfo*	addr = NULL;
	struct listensock*	accept_watch = NULL;
	int					rc = 0;
	evhttp_err			err = {NULL, EVHTTP_OK};

	memset(&hints, 0, sizeof hints);
	//hints.ai_family		= AF_INET;
	hints.ai_socktype	= SOCK_STREAM;
	hints.ai_protocol	= 0;
	if ((rc = getaddrinfo(node, service, &hints, &res))) {
		err = ERR("Could not resolve listen address", EVHTTP_ERR_LISTEN);
		if (rc == EAI_SYSTEM) {
			perror(err.msg);
		} else {
			fprintf(stderr, "%s: %s\n", err.msg, gai_strerror(rc));
		}
		goto finally;
	}

	for (addr=res; addr; addr=addr->ai_next) {
		int				listen_fd_http;
		int				enabled = 1;

		listen_fd_http = socket(addr->ai_family, addr->ai_socktype | SOCK_CLOEXEC | SOCK_NONBLOCK, addr->ai_protocol);
		if (listen_fd_http == -1) {
			err = ERR("Could not create socket", EVHTTP_ERR_SOCK);
			perror(err.msg);
			goto finally;
		}

		if (-1 == setsockopt(listen_fd_http, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(int))) {
			err = ERR("Could not set SO_REUSEADDR", EVHTTP_ERR_SOCKOPT);
			perror(err.msg);
			goto finally;
		}

		if (-1 == bind(listen_fd_http, addr->ai_addr, addr->ai_addrlen)) {
			err = ERR("Could not bind to address", EVHTTP_ERR_BIND);
			perror(err.msg);
			goto finally;
		}

		if (-1 == listen(listen_fd_http, 1024)) {
			err = ERR("Could not listen on socket", EVHTTP_ERR_LISTEN);
			perror(err.msg);
			goto finally;
		}

		accept_watch = malloc(sizeof *accept_watch);
		memset(accept_watch, 0, sizeof *accept_watch);
		accept_watch->msg_queue = q;
		ev_io_init((struct ev_io*)accept_watch, accept_cb, listen_fd_http, EV_READ);
		post_listensock(accept_watch);
	}

finally:
	freeaddrinfo(res);
	return err;
}

//>>>
void got_msg_cb(struct con_watch* w) //<<<
{
	evhttp_err			err = {NULL, EVHTTP_OK};
	struct evhttp_con*	c = w->w.data;
	struct obstack*		ob = obstack_pool_get(OBSTACK_POOL_SMALL);

#undef MSG
#define MSG "got_msg_cb"
	ts_puts(c, MSG, sizeof(MSG)-1);
	ts_log_output(c);

	c->status_numeric = 501;		// Not implemented
#define REASON	"Not Implemented"

	// Assemble body
	obstack_grow(ob, REASON, sizeof(REASON)-1);
	const size_t			body_len = obstack_object_size(ob);
	const unsigned char*	body = obstack_finish(ob);

	memset(&c->out_headers, 0, sizeof(struct headers));
	init_headers(&c->out_headers);
	c->out_headers.dl.head = NULL;
	c->out_headers.dl.tail = NULL;
#define ADD_STATIC_HEADER(hdrname, strval) \
	do { \
		struct header*	h = obstack_alloc(ob, sizeof(struct header)); \
		h->field_name = EVHTTP_HDR_OTHER; \
		h->field_name_str = (unsigned char*)hdrname; \
		h->field_name_str_len = sizeof(hdrname)-1; \
		h->field_value.str = (unsigned char*)strval; \
		h->dl.next = h->dl.prev = NULL; \
		append_header(&c->out_headers, h); \
	} while(0);

	ADD_STATIC_HEADER("Server",			"evhttp 0.1");
	// TODO: Date, etc
	ADD_STATIC_HEADER("Connection",		"close");
	ADD_STATIC_HEADER("Content-Type",	"text/plain;charset=utf-8");

	struct header*	h = obstack_alloc(ob, sizeof(struct header));
	h->field_name = EVHTTP_HDR_CONTENT_LENGTH;
	h->field_value.integer = body_len;
	h->dl.next = h->dl.prev = NULL;
	append_header(&c->out_headers, h);

#define HTTPVER	"HTTP/1.1"
	obstack_grow(ob, HTTPVER, sizeof(HTTPVER)-1);
	unsigned char* statusbase = obstack_base(ob) + obstack_object_size(ob);
	obstack_blank(ob, 5);
	statusbase[0] = ' ';
	statusbase[1] = ((c->status_numeric / 100) % 10) + '0';
	statusbase[2] = ((c->status_numeric / 10 ) % 10) + '0';
	statusbase[3] = ((c->status_numeric      ) % 10) + '0';
	statusbase[4] = ' ';
	obstack_grow(ob, REASON "\r\n", sizeof(REASON "\r\n")-1);

	err = serialize_headers(ob, &c->out_headers);
	if (err.msg) {
		ts_log(c, "Error serializing headers %s", err.msg);
		close_con(w);
		return;
	}

	const size_t			hdrbuf_len = obstack_object_size(ob);
	const unsigned char*	hdrbuf = obstack_finish(ob);
	struct write_job*		write_headers = obstack_alloc(ob, sizeof *write_headers);
	write_headers->source = WRITE_SOURCE_BUF;
	write_headers->src.buf.len = hdrbuf_len;
	write_headers->src.buf.buf = hdrbuf;
	write_headers->src.buf.written = 0;
	write_headers->action = WRITE_COMPLETE_IGNORE;
	write_headers->ob = NULL;
	write_headers->free_cb = NULL;
	write_headers->notify_loop = NULL;
	write_headers->notify_w = NULL;
	dlist_append(&c->write_jobs, write_headers);

	struct write_job*		write_body = obstack_alloc(ob, sizeof *write_body);
	memset(write_body, 0, sizeof *write_body);
	write_body->source = WRITE_SOURCE_BUF;
	write_body->src.buf.len = body_len;
	write_body->src.buf.buf = body;
	write_body->src.buf.written = 0;
	write_body->action = WRITE_COMPLETE_CLOSE;
	write_body->ob = ob;
	write_body->free_cb = &release_write_job_obstack;
	write_headers->notify_loop = NULL;
	write_headers->notify_w = NULL;
	dlist_append(&c->write_jobs, write_body);

#undef MSG
#define MSG	"Constructed response"
	ts_puts(c, MSG, sizeof(MSG)-1);

	uint64_t	q1 = nanoseconds_process_cpu();
	// TODO: pass back to the io_thread to write the data out to the socket
	pthread_mutex_lock(&write_message_queue_mutex);
	dlist_append(&g_write_message_queue, w);
	w = NULL; c = NULL;		// Ownership transferred to io thread
	pthread_mutex_unlock(&write_message_queue_mutex);

	ev_async_send(io_thread_loop, &io_thread_wakeup);
	uint64_t	q2 = nanoseconds_process_cpu();

	printf("Queued write job for io thread: %ld cycles\n", q2-q1);
#undef ADD_STATIC_HEADER
}

//>>>
struct msg_queue* new_msg_queue(int epollfd, evhttp_msg_handler* cb) //<<<
{
	struct msg_queue*	q = malloc(sizeof *q);
	struct epoll_event	ev;

	memset(q, 0, sizeof *q);
	pthread_mutex_init(&q->msgs_mutex, NULL);
	q->evfd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	q->cb = cb;

	ev.events = EPOLLIN;
	ev.data.fd = q->evfd;
	if (-1 == epoll_ctl(epollfd, EPOLL_CTL_ADD, q->evfd, &ev)) {
		perror("epoll_ctl msg_queue evfd");
		goto failed;
	}

	return q;

failed:
	if (q) {
		if (q->evfd)
			close(q->evfd);
		pthread_mutex_destroy(&q->msgs_mutex);
		free(q);
		q = NULL;
	}
	return NULL;
}

//>>>
void evhttp_handle_events(struct evhttp* evh) //<<<
{
#define MAX_EVENTS	10
	struct epoll_event	events[MAX_EVENTS];
	const int nfds = epoll_wait(evh->epollfd, events, MAX_EVENTS, 0);
	if (-1 == nfds) {
		perror("epoll_wait");
		goto failed;
	}

	for (int i=0; i<nfds; i++) {
		uint64_t	val;
		struct dlist		msgs;
		struct con_watch*	w;

		if (events[i].data.fd != evh->q->evfd) {
			// Not an fd we recognise - should only have the message queue eventfd registered
			// TODO: what?
			continue;
		}

		if (-1 == read(events[i].data.fd, &val, sizeof val)) {
			if (errno == EAGAIN) continue;
			perror("Read msg_queue evfd");
			// TODO: what?
			goto failed;
		}
		if (val == 0) continue;
		printf("Woke up for msg_queue fd %d with %ld events\n", events[i].data.fd, val);

		pthread_mutex_lock(&evh->q->msgs_mutex);
		msgs = evh->q->msgs;
		evh->q->msgs.head = evh->q->msgs.tail = NULL;
		pthread_mutex_unlock(&evh->q->msgs_mutex);

		while ((w = dlist_pop_head(&msgs)))
			evh->q->cb((struct evhttp_con*)(w->w.data));
	}

failed:
	return;
}

//>>>
int autoinit_io_thread() // Start the io thread if it hasn't been <<<
{
	int					io_thread_started = -1;
	int					rc = 0;
	pthread_t			tid;
	pthread_attr_t		attr;

#define PTHREAD_OK(call, msg) \
	do { \
		__typeof__(call) rc = call; \
		if (rc) { \
			errno = rc; \
			perror(msg); \
			return 1; \
		} \
	} while(0);

	if (autoinit_done) return 0;

	pthread_mutex_lock(&autoinit_mutex);
	if (!autoinit_done) {
		io_thread_started = eventfd(0, EFD_CLOEXEC);
		if (-1 == io_thread_started) {
			perror("eventfd io_thread_started");
			goto failed;
		}
		PTHREAD_OK(pthread_attr_init(&attr), "pthread_attr_init failed");
		PTHREAD_OK(pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED), "pthread_attr_setdetachstate failed");
		PTHREAD_OK(pthread_create(&tid, &attr, thread_start, &io_thread_started), "pthread_create failed");
		PTHREAD_OK(pthread_attr_destroy(&attr), "pthread_attr_destroy failed");

		uint64_t val;
		rc = read(io_thread_started, &val, sizeof val);
		if (-1 == rc) {
			perror("Read io_thread_started eventfd");
			exit(EXIT_FAILURE);
		}
		rc = val - 256;
		printf("Got io_thread startup result: %d\n", rc);
		if (-1 == rc) {
			fprintf(stderr, "io thread startup failed\n");
			goto failed;
		}
		autoinit_done = 1;
	}

failed:
	if (io_thread_started != -1) close(io_thread_started);
	pthread_mutex_unlock(&autoinit_mutex);

	return rc;
}

//>>>
evhttp_err evhttp_server(evhttp_msg_handler* cb, struct evhttp** evh) //<<<
{
	struct evhttp*		new_evh = NULL;

	if (-1 == autoinit_io_thread()) {
		goto failed;
	}

	new_evh = malloc(sizeof *new_evh);
	memset(new_evh, 0, sizeof *new_evh);

	new_evh->epollfd = epoll_create1(0);
	if (-1 == new_evh->epollfd) {
		perror("Could not create epoll instance");
		exit(EXIT_FAILURE);
	}

	// Create a queue for receiving messages from our listening sockets
	new_evh->q = new_msg_queue(new_evh->epollfd, cb);

	*evh = new_evh;
	return ERR(NULL, EVHTTP_OK);

failed:
	if (new_evh) {
		free(new_evh);
		new_evh = NULL;
	}
	return ERR("Could not create new evhttp_server");
}

//>>>
evhttp_err evhttp_server_listen(struct evhttp* evh, const char* node, const char* service) //<<<
{
	return start_listen(evh->q, node, service);
}

//>>>
int evhttp_fd(struct evhttp* evh) //<<<
{
	return evh->epollfd;
}

//>>>
size_t evhttp_con_get_body_len(struct evhttp_con* con) //<<<
{
	return con->body_size;
}

//>>>
const unsigned char* evhttp_con_get_body(struct evhttp_con* con) //<<<
{
	return con->body;
}

//>>>
enum evhttp_method evhttp_con_get_method(struct evhttp_con* con) //<<<
{
	return con->method;
}

//>>>
evhttp_err evhttp_con_set_status_(struct evhttp_con_set_status_args args) //<<<
{
	struct evhttp_con*	c = args.con;
	evhttp_err			err = {NULL, EVHTTP_OK};

	if (args.status < 100 || args.status >= 600) {
		err = ERR("Status must be in the range [100, 600]", EVHTTP_ERR_INVALID);
		goto finally;
	}

	c->status_numeric = args.status;

	if (args.reason.bytes)
		c->reason = args.reason;

finally:
	return err;
}

//>>>
#if 0
int evhttp_con_set_body(struct evhttp_con* con, const char* content_type, const char* body, ssize_t body_len) //<<<
{
	struct obstack*	ob = obstack_pool_get(OBSTACK_POOL_SMALL);

	// Assemble body
	obstack_grow(ob, "Bad Request", sizeof("Bad Request")-1);
	const size_t			body_len = obstack_object_size(ob);
	const unsigned char*	body = obstack_finish(ob);

	init_headers(&c->out_headers);
#define ADD_STATIC_HEADER(hdrname, strval) \
	do { \
		struct header*	h = obstack_alloc(ob, sizeof(struct header)); \
		h->field_name = EVHTTP_HDR_OTHER; \
		h->field_name_str = (unsigned char*)hdrname; \
		h->field_name_str_len = sizeof(hdrname)-1; \
		h->field_value.str = (unsigned char*)strval; \
		append_header(&c->out_headers, h); \
	} while(0);

	ADD_STATIC_HEADER("Server",			"evhttp 0.1");
	// TODO: Date, etc
	ADD_STATIC_HEADER("Connection",		"close");
	ADD_STATIC_HEADER("Content-Type",	"text/plain;charset=utf-8");

	struct header*	h = obstack_alloc(ob, sizeof(struct header));
	h->field_name = EVHTTP_HDR_CONTENT_LENGTH;
	h->field_value.integer = body_len;
	append_header(&c->out_headers, h);

	obstack_grow(ob, "HTTP/1.1 400 Bad Request\r\n", sizeof("HTTP/1.1 400 Bad Request\r\n")-1);
	if (serialize_headers(ob, &c->out_headers)) {
		ts_puts(c, "Error serializing headers", sizeof("Error serializing headers"));
		goto close;
	}

	const size_t			hdrbuf_len = obstack_object_size(ob);
	const unsigned char*	hdrbuf = obstack_finish(ob);
	struct write_job*		write_headers = obstack_alloc(ob, sizeof *write_headers);
	memset(write_headers, 0, sizeof *write_headers);
	write_headers->source = WRITE_SOURCE_BUF;
	write_headers->src.buf.len = hdrbuf_len;
	write_headers->src.buf.buf = hdrbuf;
	write_headers->action = WRITE_COMPLETE_IGNORE;
	dlist_append(&c->write_jobs, write_headers);

	struct write_job*		write_body = obstack_alloc(ob, sizeof *write_body);
	memset(write_body, 0, sizeof *write_body);
	write_body->source = WRITE_SOURCE_BUF;
	write_body->src.buf.len = body_len;
	write_body->src.buf.buf = body;
	write_body->action = WRITE_COMPLETE_CLOSE;
	write_body->ob = ob;
	write_body->free_cb = &release_write_job_obstack;
	dlist_append(&c->write_jobs, write_body);

	if (w->w.events & EV_READ)
		modify_io_evmask(loop, (struct ev_io*)w, 0, EV_READ);

	ts_puts(c, "Constucted and queued response", sizeof("Constucted and queued response")-1);
	con_io_cb(loop, (struct ev_io*)w, EV_WRITE);
#undef ADD_STATIC_HEADER
}

//>>>
#endif
//evhttp_err evhttp_con_set_body(struct evhttp_con* con, const char* content_type, const char* body, ssize_t body_len, evhttp_releaser* free_body)
evhttp_err evhttp_con_set_body_(struct evhttp_con_set_body_args args) //<<<
{
	evhttp_err			err = {NULL, EVHTTP_OK};
	struct evhttp_con*	con = args.con;
	const char*			content_type = args.content_type ? args.content_type : "text/plain";

	if (!con) {
		err = ERR("con is NULL", EVHTTP_ERR_INVALID);
		goto finally;
	}

	if (con->body_write_job) {
		// There is already a body writer queued, replace it
		if (con->body_write_job->free_cb) {
			void*	free_cdata = con->body_write_job->free_cdata;
			if (free_cdata == NULL) free_cdata = con->body_write_job;
			con->body_write_job->free_cb(free_cdata);
		}
		con->body_write_job = NULL;
	}

	switch (args.source) {
		case EVHTTP_SOURCE_BUF:
			{
				const char*			body = args.buf.bytes;
				ssize_t				body_len = args.buf.len ? args.buf.len : -1;
				evhttp_releaser*	free_body = args.buf.free;

				if (body == NULL)
					goto finally;

				if (body_len == -1)
					body_len = strlen(body);

				EVHTTP_CHECK(finally, err, evhttp_con_set_header(con, EVHTTP_HDR_OTHER, "Content-Type", .value=content_type));
				EVHTTP_CHECK(finally, err, evhttp_con_set_header(con, EVHTTP_HDR_CONTENT_LENGTH, .value.integer=body_len));

				con->body_write_job = obstack_alloc(con->ob, sizeof(struct write_job));
				memset(con->body_write_job, 0, sizeof(struct write_job));
				con->body_write_job->source = WRITE_SOURCE_BUF;
				con->body_write_job->src.buf.len = body_len;
				con->body_write_job->src.buf.buf = (const unsigned char*)body;
				con->body_write_job->action = WRITE_COMPLETE_IGNORE;
				con->body_write_job->free_cb = free_body;
				con->body_write_job->free_cdata = (void*)body;
			}
			break;

		case EVHTTP_SOURCE_STREAM:
			err = ERR("EVHTTP_SOURCE_STREAM not implemented yet", EVHTTP_ERR_UNIMPLEMENTED);
			break;

		default:
			err = ERR("Invalid source", EVHTTP_ERR_INVALID);
			break;
	}

finally:
	return err;
}

//>>>
int evhttp_con_target_match(struct evhttp_con* con, const char* target_pattern) //<<<
{
	// TODO: make this smarter
	return strcmp(target_pattern, (const char*)con->target) == 0;
}

//>>>
evhttp_err append_statusline(struct obstack* ob, const unsigned char* http_ver, int status, struct evhttp_buf* reason) //<<<
{
	evhttp_err	err = {NULL, EVHTTP_OK};
	const int	restore_size = obstack_object_size(ob);

	if (status < 100 || status >= 600)
		return ERR("Status must be in the range [100, 600]", EVHTTP_ERR_INVALID);

	obstack_grow(ob, http_ver, strlen((const char*)http_ver));
	obstack_1grow(ob, ' ');
	obstack_1grow(ob, '0' + ((status / 100) % 10));
	obstack_1grow(ob, '0' + ((status / 10)  % 10));
	obstack_1grow(ob, '0' + ( status        % 10));
	obstack_1grow(ob, ' ');
	if (reason->bytes) {
		const size_t	len = reason->len == -1 ? strlen(reason->bytes) : reason->len;

		if (len == 0) {
			err = ERR("Reason cannot be blank", EVHTTP_ERR_INVALID);
			goto finally;
		}
		obstack_grow(ob, reason->bytes, len);
	} else { // Provide a standard reason for status <<<
		const char*	default_reason = NULL;
		size_t		default_reason_len;

#define DEFAULT_REASON(msg) do {default_reason=msg; default_reason_len=sizeof(msg)-1;} while(0)
		switch (status) {
			case 100: DEFAULT_REASON("Continue");							break;
			case 101: DEFAULT_REASON("Switching Protocols");				break;
			case 102: DEFAULT_REASON("Processing");							break;
			case 103: DEFAULT_REASON("Early Hints");						break;

			case 200: DEFAULT_REASON("OK");									break;
			case 201: DEFAULT_REASON("Created");							break;
			case 202: DEFAULT_REASON("Accepted");							break;
			case 203: DEFAULT_REASON("Non-Authoritative Information");		break;
			case 204: DEFAULT_REASON("No Content");							break;
			case 205: DEFAULT_REASON("Reset Content");						break;
			case 206: DEFAULT_REASON("Partial Content");					break;
			case 207: DEFAULT_REASON("Multi-Status");						break;
			case 208: DEFAULT_REASON("Already Reported");					break;
			case 226: DEFAULT_REASON("IM Used");							break;

			case 300: DEFAULT_REASON("Multiple Choices");					break;
			case 301: DEFAULT_REASON("Moved Permanently");					break;
			case 302: DEFAULT_REASON("Found");								break;
			case 303: DEFAULT_REASON("See Other");							break;
			case 304: DEFAULT_REASON("Not Modified");						break;
			case 305: DEFAULT_REASON("Use Proxy");							break;
			case 306: DEFAULT_REASON("Switch Proxy");						break;
			case 307: DEFAULT_REASON("Temporary Redirect");					break;
			case 308: DEFAULT_REASON("Permanent Redirect");					break;

			case 400: DEFAULT_REASON("Bad Request");						break;
			case 401: DEFAULT_REASON("Unauthorized");						break;
			case 402: DEFAULT_REASON("Payment Required");					break;
			case 403: DEFAULT_REASON("Forbidden");							break;
			case 404: DEFAULT_REASON("Not Found");							break;
			case 405: DEFAULT_REASON("Method Not Allowed");					break;
			case 406: DEFAULT_REASON("Not Acceptable");						break;
			case 407: DEFAULT_REASON("Proxy Authentication Required");		break;
			case 408: DEFAULT_REASON("Request Timeout");					break;
			case 409: DEFAULT_REASON("Conflict");							break;
			case 410: DEFAULT_REASON("Gone");								break;
			case 411: DEFAULT_REASON("Length Required");					break;
			case 412: DEFAULT_REASON("Precondition Failed");				break;
			case 413: DEFAULT_REASON("Payload Too Large");					break;
			case 414: DEFAULT_REASON("URI Too Long");						break;
			case 415: DEFAULT_REASON("Unsupported Media Type");				break;
			case 416: DEFAULT_REASON("Range Not Satisfiable");				break;
			case 417: DEFAULT_REASON("Expectation Failed");					break;
			case 418: DEFAULT_REASON("I'm a teapot");						break;
			case 421: DEFAULT_REASON("Misdirected Request");				break;
			case 422: DEFAULT_REASON("Unprocessable Entity");				break;
			case 423: DEFAULT_REASON("Locked");								break;
			case 424: DEFAULT_REASON("Failed Dependency");					break;
			case 425: DEFAULT_REASON("Too Early");							break;
			case 426: DEFAULT_REASON("Upgrade Required");					break;
			case 428: DEFAULT_REASON("Precondition Required");				break;
			case 429: DEFAULT_REASON("Too Many Requests");					break;
			case 431: DEFAULT_REASON("Request Header Fields Too Large");	break;
			case 451: DEFAULT_REASON("Unavailable For Legal Reasons");		break;

			case 500: DEFAULT_REASON("Internal Server Error");				break;
			case 501: DEFAULT_REASON("Not Implemented");					break;
			case 502: DEFAULT_REASON("Bad Gateway");						break;
			case 503: DEFAULT_REASON("Service Unavailable");				break;
			case 504: DEFAULT_REASON("Gateway Timeout");					break;
			case 505: DEFAULT_REASON("HTTP Version Not Supported");			break;
			case 506: DEFAULT_REASON("Variant Also Negotiates");			break;
			case 507: DEFAULT_REASON("Insufficient Storage");				break;
			case 508: DEFAULT_REASON("Loop Detected");						break;
			case 510: DEFAULT_REASON("Not Extended");						break;
			case 511: DEFAULT_REASON("Network Authentication Required");	break;

			default:
				     if (status <= 199)	DEFAULT_REASON("Informational");
				else if (status <= 299)	DEFAULT_REASON("Success");
				else if (status <= 399)	DEFAULT_REASON("Redirection");
				else if (status <= 499)	DEFAULT_REASON("Client Error");
				else if (status <= 599)	DEFAULT_REASON("Server Error");
		}
#undef DEFAULT_REASON
		obstack_grow(ob, default_reason, default_reason_len);
		//>>>
	}
	obstack_grow(ob, "\r\n", 2);

finally:
	if (err.msg)
		obstack_free(ob, obstack_base(ob) + restore_size);

	return err;
}

//>>>
evhttp_err evhttp_con_set_header_(struct evhttp_con_set_header_args args) //<<<
{
	evhttp_err			err = {NULL, EVHTTP_OK};
	struct evhttp_con*	con = args.con;
	struct header*		h = obstack_alloc(con->ob, sizeof *h);

	h->field_name = args.name;
	if (h->field_name == EVHTTP_HDR_OTHER) {
		if (args.name_str.bytes == NULL) {
			err = ERR(".name_str must be set if .name == EVHTTP_HDR_OTHER", EVHTTP_ERR_INVALID);
			goto finally;	
		}
		h->field_name_str = (unsigned char*)strdup(args.name_str.bytes);	// TODO: fix leak
		h->field_name_str_len = args.name_str.len > 0 ? args.name_str.len : strlen((char*)h->field_name_str);
		//h->field_name_str_free = args.name_str.free; // TODO
	}

	switch (h->field_name) {
		case EVHTTP_HDR_OTHER:
		case EVHTTP_HDR_HOST:
		case EVHTTP_HDR_USER_AGENT:
			h->field_value.str = (unsigned char*)strdup(args.value.str.bytes);	// TODO: fix leak
			//h->field_value.str_len = args.value.str.len;		// TODO
			//h->field_value.str_free = args.value.str.free;	// TODO
			break;

		case EVHTTP_HDR_CONTENT_LENGTH:
			h->field_value.integer = args.value.integer;
			break;

		case EVHTTP_HDR_CONTENT_TYPE:
		case EVHTTP_HDR_TRANSFER_ENCODING:
		case EVHTTP_HDR_TE:
		case EVHTTP_HDR_SET_COOKIE:
		case EVHTTP_HDR_COOKIE:
		case EVHTTP_HDR_CONNECTION:
		case EVHTTP_HDR_UPGRADE:
			err = ERR("Header not implemented yet", EVHTTP_ERR_UNIMPLEMENTED);
			goto finally;

		default:
			err = ERR("Invalid header", EVHTTP_ERR_INVALID);
			goto finally;
	}

finally:
	if (err.msg)
		obstack_free(con->ob, h);

	return err;
}

//>>>
evhttp_err evhttp_con_respond(struct evhttp_con* con) //<<<
{
	evhttp_err			err = {NULL, EVHTTP_OK};

#define ADD_STATIC_HEADER(hdrname, strval) \
	do { \
		struct header*	h = obstack_alloc(con->ob, sizeof(struct header)); \
		h->field_name = EVHTTP_HDR_OTHER; \
		h->field_name_str = (unsigned char*)hdrname; \
		h->field_name_str_len = sizeof(hdrname)-1; \
		h->field_value.str = (unsigned char*)strval; \
		append_header(&con->out_headers, h); \
	} while(0);

	if (con->body_write_job) {
		const struct write_job*	j = con->body_write_job;
		if (j->source == WRITE_SOURCE_BUF) {
			struct header*	h = obstack_alloc(con->ob, sizeof(struct header));
			h->field_name = EVHTTP_HDR_CONTENT_LENGTH;
			h->field_value.integer = j->src.buf.len;
			append_header(&con->out_headers, h);
		} else {
			// TODO: Transfer-Encoding: chunked
			err = ERR("Transfer-Encoding: chunked is not supported yet", EVHTTP_ERR_UNIMPLEMENTED);
			goto finally;
		}
	} else {
		struct header*	h = obstack_alloc(con->ob, sizeof(struct header));
		h->field_name = EVHTTP_HDR_CONTENT_LENGTH;
		h->field_value.integer = 0;
		append_header(&con->out_headers, h);
	}

	ADD_STATIC_HEADER("Server",			"evhttp 0.1");
	// TODO: Date, etc
	//ADD_STATIC_HEADER("Connection",	"close");
	//ADD_STATIC_HEADER("Content-Type",	"text/plain;charset=utf-8");

	EVHTTP_CHECK(finally, err, append_statusline(con->ob, con->http_ver, con->status_numeric, &con->reason));
	EVHTTP_CHECK(finally, err, serialize_headers(con->ob, &con->out_headers));

	const size_t			hdrbuf_len = obstack_object_size(con->ob);
	const unsigned char*	hdrbuf = obstack_finish(con->ob);
	enum write_complete_action	final_action = con->connectionflags & CON_CLOSE ? WRITE_COMPLETE_CLOSE : WRITE_COMPLETE_IGNORE;
	struct write_job*		write_headers = obstack_alloc(con->ob, sizeof *write_headers);
	memset(write_headers, 0, sizeof *write_headers);
	write_headers->source = WRITE_SOURCE_BUF;
	write_headers->src.buf.len = hdrbuf_len;
	write_headers->src.buf.buf = hdrbuf;
	write_headers->action = WRITE_COMPLETE_IGNORE;
	dlist_append(&con->write_jobs, write_headers);

	if (con->body_write_job) {
		if (
				(con->role == CON_ROLE_SERVER && con->method == EVHTTP_METHOD_HEAD) ||
				(con->role == CON_ROLE_SERVER && con->method == EVHTTP_METHOD_CONNECT) ||
				(con->status_numeric >= 100 && con->status_numeric <= 199) ||
				con->status_numeric == 204 ||
				con->status_numeric == 304
		) {
			err = ERR("Body is not allowed for this type of response", EVHTTP_ERR_INVALID);
			goto finally;
		}

		con->body_write_job->action = final_action;
		dlist_append(&con->write_jobs, con->body_write_job);
	} else {
		write_headers->action = final_action;
	}

	/*
	if (con->w->w.events & EV_READ)
		modify_io_evmask(con->w->loop, (struct ev_io*)con->w, 0, EV_READ);
		*/

	con_io_cb(con->w->loop, (struct ev_io*)con->w, EV_WRITE);
	ts_puts(con, STATIC_STR("Constucted and queued response"));
#undef ADD_STATIC_HEADER

finally:
	return err;
}

//>>>
evhttp_err evhttp_close(struct evhttp** evh) //<<<
{
	evhttp_err			err = {NULL, EVHTTP_OK};

	if (*evh == NULL) goto finally;

	// TODO: everything

	if ((*evh)->epollfd > 0) {
		close((*evh)->epollfd);
		(*evh)->epollfd = -1;
	}

	if ((*evh)->q) {
		struct msg_queue*	q = (*evh)->q;
		struct listensock*	sock = NULL;

		pthread_mutex_lock(&listensock_mutex);
		sock = g_listensock_active.head;
		while (sock) {
			struct listensock*	s = sock;
			if (sock->msg_queue == q) {
				ev_io_stop(io_thread_loop, &sock->accept_watcher);
				close(sock->accept_watcher.fd);
				//free(sock->accept_watcher);
				//sock->accept_watcher = NULL;
				g_listensock_active.head = sock->next;

				pthread_mutex_lock(&sock->msg_queue->msgs_mutex);
				close(sock->msg_queue->evfd);
				sock->msg_queue->evfd = -1;
				sock->msg_queue->cb = NULL;
				pthread_mutex_unlock(&sock->msg_queue->msgs_mutex);
			}

			sock = sock->next;

			// TODO: reference-count the listensock struct, dec the listener ref here
			free(s);
			s = NULL;
		}
		if (g_listensock_active.tail) {
			g_listensock_active.tail->next = g_listensock_queue.head;
			g_listensock_active.tail = g_listensock_queue.tail;
		} else {
			g_listensock_active.head = g_listensock_queue.head;
			g_listensock_active.tail = g_listensock_queue.tail;
		}
		g_listensock_queue.head = g_listensock_queue.tail = NULL;
		pthread_mutex_unlock(&listensock_mutex);
		pthread_mutex_lock(&q->msgs_mutex);
		(*evh)->q = NULL;
		pthread_mutex_unlock(&q->msgs_mutex);
		pthread_mutex_destroy(&q->msgs_mutex);
		if (q->evfd > 0) {
			close(q->evfd);
			q->evfd = -1;
		}
		free(q);
		q = NULL;
	}

	free(*evh);
	*evh = NULL;

finally:
	return err;
}

//>>>

// vim: ft=c foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4
