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

static struct ev_loop*		main_loop = NULL;
static struct ev_loop*		io_thread_loop = NULL;
static struct ev_async		io_thread_wakeup;

pthread_mutex_t		listensock_mutex = PTHREAD_MUTEX_INITIALIZER;
struct listensock_queue g_listensock_queue = {
	.head = NULL,
	.tail = NULL
};

struct listensock_queue g_listensock_active = {
	.head = NULL,
	.tail = NULL
};

//thread_local struct perf_event_attr	t_pe = {0};
thread_local int		t_cpu_cycles_fd;
thread_local uint64_t	t_overhead = 0;
thread_local uint64_t	t_overhead_compensation = 0;

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
static void io_thread_wakeup_cb(struct ev_loop* loop, struct ev_async* w, int revents) //<<<
{
	struct listensock*	sock = NULL;

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

//>>>
void close_t_cpu_cycles_fd(void* cdata) //<<<
{
	const pthread_t	tid = pthread_self();
	//fprintf(stderr, "Closing t_cpu_cycles_fd in %s (%p)\n", name(tid), tid);
	fprintf(stderr, "Closing t_cpu_cycles_fd in %ld\n", tid);
	close(t_cpu_cycles_fd);
}

//>>>
static void* thread_start(void* cdata) //<<<
{
	struct timespec after;
	double delta;
	struct perf_event_attr	pe = {0};

	clock_gettime(CLOCK_MONOTONIC, &after);

	io_thread_loop = ev_loop_new(EVFLAG_AUTO);
	if (io_thread_loop == NULL) {
		fprintf(stderr, "Could not initialize thread loop\n");
		pthread_exit(NULL);
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

	// Need to set /proc/sys/kernel/perf_event_paranoid to 0 to use without root
	t_cpu_cycles_fd = perf_event_open(&pe, 0, -1, -1, 0);
	if (t_cpu_cycles_fd == -1) {
		perror("Could not open t_cpu_cycles_fd");
		pthread_exit(NULL);
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

	delta = after.tv_sec - before.tv_sec + (after.tv_nsec - before.tv_nsec)/1e9 - empty;
	fprintf(stderr, "io_thread start latency: %.1f microseconds\n", delta*1e6);

	printf("In thread %ld\n", pthread_self());

	ev_run(io_thread_loop, 0);
	ev_loop_destroy(io_thread_loop);

	pthread_cleanup_pop(1);
	return NULL;
}

//>>>
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
#if 0
void respond(struct ev_io* w, int status, struct headers* headers, struct body_source* body, enum aio_action action) //<<<
{
	struct aio_done_action*		on_complete = malloc(sizeof *on_complete);

	on_complete->con_watch = w;
	on_complete->aio_action = action;
	on_complete->notify_w = NULL;
	on_complete->aiocb = {
		.aio_filedes	= w->fd,
		.aio_offset		= 0,
		.aio_buf		= NULL,	// TODO
		.aio_nbytes		= 0,	// TODO
		.aio_sigevent	= {
			.sigev_notify	= SIGEV_THREAD
		}
	};
}

//>>>
#endif
void con_readable_cb(struct ev_loop* loop, struct ev_io* w, int revents) //<<<
{
	struct con_state*	c = w->data;

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
					remain = c->headers.first[HDR_CONTENT_LENGTH]->field_value.integer - c->body_size;
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

					default:
						fprintf(stderr, "Unhandled body_storage: %d\n", c->body_storage);
						goto close_500;
				}
			}

			// Grow the body allocation if needed >>>
			// Read more body bytes <<<
			got = read(w->fd, c->body + c->body_size, remain);
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

			if (shift) {
				//report("shifting to", c->tok);
				shift_msg_buffer(c, shift);
			}

			const ssize_t got = read(w->fd, c->lim, c->buf_size - (c->lim - c->buf));
			if (got == -1) {
				switch (errno) {
#if EAGAIN != EWOULDBLOCK
					case EWOULDBLOCK:
#endif
					case EAGAIN:
						if (c->cur < c->lim) break;	// May not have read any more, but we have some already waiting
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

			ts_log(c, "read: %ld bytes", got);
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
							(c->role == CON_ROLE_CLIENT && c->method == METHOD_HEAD) ||
							(c->role == CON_ROLE_CLIENT && c->method == METHOD_CONNECT) ||
							(c->status_numeric >= 100 && c->status_numeric <= 199) ||
							c->status_numeric == 204 ||
							c->status_numeric == 304
					) {
						// No body, regardless of any header fields that might indicate a length
						c->body_len = BODY_LEN_NONE;
					} else if (c->headers.first[HDR_TRANSFER_ENCODING]) { // Transfer-Encoding present
						if (c->headers.first[HDR_CONTENT_LENGTH]) {
							// MUST strip content_length if it was present
							remove_header(&c->headers, c->headers.first[HDR_CONTENT_LENGTH]);
						}

						if (last_header(&c->headers, HDR_TRANSFER_ENCODING)->field_value.integer == TE_CHUNKED) {
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
					} else if (c->headers.first[HDR_CONTENT_LENGTH]) {
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
								const int content_length = c->headers.first[HDR_CONTENT_LENGTH]->field_value.integer;
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

	return;

close:
	close(w->fd);
	ev_io_stop(loop, w);
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
	//c->headers = {0};
	ts_log_output(c);
	obstack_pool_release(c->logs);
	obstack_pool_release(c->ob);
	w->data = NULL;
	free(w);
	w = NULL;
	return;

close_400:
	// TODO: Respond with 400 Bad Request and close
	goto close;
	return;

close_500:
	// TODO: Respond with 500 Bad Request and close
	goto close;
	return;

	

message_complete:
	if (w) {
		ev_io_stop(loop, w);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wparentheses"
		ev_io_modify(w, 0);		// Disable callbacks for this fd while the message is processed
#pragma GCC diagnostic pop
	}
	ts_puts(c, "Message complete", sizeof("Message complete"));
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
	}
	obstack_pool_release(ob); ob = NULL;
	goto close;
	return;
}

//>>>
void accept_cb(struct ev_loop* loop, struct ev_io* w, int revents) //<<<
{
	uint64_t					accept_start = nanoseconds_process_cpu();
	int							con_fd;
	struct sockaddr_storage		con_addr;
	struct ev_io*				con_watch = NULL;
	struct con_state*			c;
	socklen_t					addrlen = sizeof con_addr;
	struct obstack*				ob;
	
	uint64_t	a1 = nanoseconds_process_cpu();
#if 0
	con_fd = accept(w->fd, (struct sockaddr*)&con_addr, &addrlen);
	if (con_fd == -1) {
		perror("Could not accept new connection");
		exit(EXIT_FAILURE);
	}
	uint64_t	a2 = nanoseconds_process_cpu();

	if (
			-1 == fcntl(con_fd, F_SETFD, FD_CLOEXEC) ||
			-1 == fcntl(con_fd, F_SETFL, O_NONBLOCK)
	) {
		perror("Could not set FD_CLOEXEC and O_NONBLOCK on con_fd");
		exit(EXIT_FAILURE);
	}
#else
	con_fd = accept4(w->fd, (struct sockaddr*)&con_addr, &addrlen, SOCK_NONBLOCK | SOCK_CLOEXEC);
	if (con_fd == -1) {
		perror("Could not accept new connection");
		exit(EXIT_FAILURE);
	}
#endif
	uint64_t	a3 = nanoseconds_process_cpu();

	uint64_t	ta = nanoseconds_process_cpu();
	ob = obstack_pool_get(OBSTACK_POOL_SMALL);
	uint64_t	tb = nanoseconds_process_cpu();
	c = obstack_alloc(ob, sizeof *c);
	uint64_t	tc = nanoseconds_process_cpu();
	c->ob				= ob;
	c->logs				= obstack_pool_get(OBSTACK_POOL_SMALL);
	c->logs_head		= NULL;
	c->logs_tail		= NULL;
	c->last_log			= accept_start;
	ts_log(c, "accept: %ld, obstack_pool_get: %ld, obstack_alloc: %ld", a3-a1, tb-ta, tc-tb);
	ts_puts(c, "Init buf start", sizeof("Init buf start"));
	init_msg_buffer(c);
	ts_puts(c, "Init buf", sizeof("Init buf"));
	c->accept_time		= accept_start;
	/*
	ts_log(c, "%s", "Allocated con_state");
	ts_log(c, "%s", "nop");
	*/
	ts_puts(c, "Allocated con_state", sizeof("Allocated con_state"));
	c->state			= -1;
	c->status			= CON_STATUS_WAITING;
	c->status_code[0]	= 0;
	c->role				= CON_ROLE_SERVER;
	c->method			= METHOD_UNSPECIFIED;
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

	init_headers(&c->headers);

	con_watch = malloc(sizeof *con_watch);
	//ev_io_init(con_watch, con_readable_cb, con_fd, EV_READ);
	ev_init(con_watch, con_readable_cb);
	ev_io_set(con_watch, con_fd, EV_READ);
	con_watch->data = c;
	ev_io_start(io_thread_loop, con_watch);
}

//>>>
void start_listen(const char* node, const char* service) //<<<
{
	struct addrinfo		hints;
	struct addrinfo*	res = NULL;
	struct addrinfo*	addr = NULL;
	struct listensock*	accept_watch = NULL;
	int					ev_pipe[2];
	int					rc;

	memset(&hints, 0, sizeof hints);
	hints.ai_family		= AF_INET;
	hints.ai_socktype	= SOCK_STREAM;
	hints.ai_protocol	= 0;
	if ((rc = getaddrinfo(NULL, "1080", &hints, &res))) {
		if (rc == EAI_SYSTEM) {
			perror("Could not resolve listen address");
		} else {
			fprintf(stderr, "Could not resolve address: %s\n", gai_strerror(rc));
		}
		exit(EXIT_FAILURE);
	}

	for (addr=res; addr; addr=addr->ai_next) {
		int				listen_fd_http;
		struct ev_io*	mainthread_ev_pipe_watch = malloc(sizeof *mainthread_ev_pipe_watch);	// LEAKS: we have no way to close the sockets these report on anyway
		int				enabled = 1;

		listen_fd_http = socket(addr->ai_family, addr->ai_socktype | SOCK_CLOEXEC | SOCK_NONBLOCK, addr->ai_protocol);
		if (listen_fd_http == -1) {
			perror("Could not create socket");
			exit(EXIT_FAILURE);
		}

		if (-1 == setsockopt(listen_fd_http, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(int))) {
			perror("Could not set SO_REUSEADDR");
			exit(EXIT_FAILURE);
		}

		if (-1 == bind(listen_fd_http, addr->ai_addr, addr->ai_addrlen)) {
			perror("Could not bind to address");
			exit(EXIT_FAILURE);
		}

		if (-1 == listen(listen_fd_http, 1024)) {
			perror("Could not listen on socket");
			exit(EXIT_FAILURE);
		}

		if (-1 == pipe(ev_pipe)) {
			perror("Could not create ev_pipe");
			exit(EXIT_FAILURE);
		}
		if (-1 == fcntl(ev_pipe[0], F_SETFL, O_NONBLOCK)) {
			perror("Could not set O_NONBLOCK and FD_CLOEXEC on ev_pipe");
			exit(EXIT_FAILURE);
		}
		if (-1 == fcntl(ev_pipe[0], F_SETFD, FD_CLOEXEC)) {
			perror("Could not set O_NONBLOCK and FD_CLOEXEC on ev_pipe");
			exit(EXIT_FAILURE);
		}
		if (-1 == fcntl(ev_pipe[1], F_SETFL, O_NONBLOCK)) {
			perror("Could not set O_NONBLOCK and FD_CLOEXEC on ev_pipe");
			exit(EXIT_FAILURE);
		}
		if (-1 == fcntl(ev_pipe[1], F_SETFD, FD_CLOEXEC)) {
			perror("Could not set O_NONBLOCK and FD_CLOEXEC on ev_pipe");
			exit(EXIT_FAILURE);
		}

		accept_watch = malloc(sizeof *accept_watch);
		ev_io_init(&accept_watch->accept_watcher, accept_cb, listen_fd_http, EV_READ);
		accept_watch->ev_pipe_w = ev_pipe[1];
		post_listensock(accept_watch);

		ev_io_init(mainthread_ev_pipe_watch, ev_pipe_cb, ev_pipe[0], EV_READ);
		ev_io_start(main_loop, mainthread_ev_pipe_watch);
	}
	freeaddrinfo(res);
}

//>>>
int main(int argc, char** argv) //<<<
{
	pthread_t		tid;
	pthread_attr_t	attr;

	main_loop = ev_default_loop(EVFLAG_AUTO);

	if (main_loop == NULL) {
		fprintf(stderr, "Could not initialize default libev loop\n");
		return 1;
	}
 
#define PTHREAD_OK(call, msg) \
	do { \
		__typeof__(call) rc = call; \
		if (rc) { \
			errno = rc; \
			perror(msg); \
			return 1; \
		} \
	} while(0);

	PTHREAD_OK(pthread_attr_init(&attr), "pthread_attr_init failed");
	PTHREAD_OK(pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED), "pthread_attr_setdetachstate failed");
	struct timespec first;
	struct timespec after;
	double delta;
	clock_gettime(CLOCK_MONOTONIC, &first);	/* Warm up the call */
	clock_gettime(CLOCK_MONOTONIC, &first);
	clock_gettime(CLOCK_MONOTONIC, &before);
	empty = before.tv_sec - first.tv_sec + (before.tv_nsec - first.tv_nsec)/1e9;
	clock_gettime(CLOCK_MONOTONIC, &before);
	PTHREAD_OK(pthread_create(&tid, &attr, thread_start, NULL), "pthread_create failed");
	clock_gettime(CLOCK_MONOTONIC, &after);
	delta = after.tv_sec - before.tv_sec + (after.tv_nsec - before.tv_nsec)/1e9 - empty;
	fprintf(stderr, "Main thread pthread_create time: %.1f microseconds\n", delta*1e6);
	PTHREAD_OK(pthread_attr_destroy(&attr), "pthread_attr_destroy failed");
	printf("In main thread, created thread %ld\n", tid);

	// TODO: properly wait for our io_thread to be ready to receive the async wakeup
	usleep(10000);
	start_listen(NULL, "1080");

	ev_run(main_loop, 0);

	pthread_exit(NULL);
}

//>>>

// vim: ft=c foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4
