#include "evhttpInt.h"

#define obstack_chunk_alloc	malloc
#define obstack_chunk_free	free
/*
static void my_obstack_alloc_failed()
{
	fprintf(stderr, "Failed to allocate memory for obstack\n");
	exit(EXIT_FAILURE);
}
*/
 
struct timespec before;
double empty = 0.0;

/*!types:re2c */
/*!include:re2c "common.reh" */

static struct ev_loop*		main_loop = NULL;
static struct ev_loop*		io_thread_loop = NULL;
static struct ev_async		io_thread_wakeup;

pthread_mutex_t		listensock_mutex = PTHREAD_MUTEX_INITIALIZER;
struct listensock_queue {
	struct listensock* head;
	struct listensock* tail;
};

struct listensock_queue g_listensock_queue = {
	.head = NULL,
	.tail = NULL
};

struct listensock_queue g_listensock_active = {
	.head = NULL,
	.tail = NULL
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
	struct dlist_elem		dl;
	const unsigned char*	token;
};

struct media_type_param {
	struct mediatype_param*	next;
	unsigned char*	name;
	unsigned char*	value;
};

struct media_type {
	const unsigned char*		media_type;
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
	BODY_STORAGE_BORROWED,		// Points at memory owned by someone else (probably the c->static_buf)
	BODY_STORAGE_MALLOC,		// Points to memory managed by malloc
	BODY_STORAGE_MMAP,			// Points to a mmap'ed region
	BODY_STORAGE_OBSTACK		// Managed by c->meta obstack
};

#define CON_STATE_SIZE				8192-32
#define TE_MAX						8
struct con_state {
	enum con_role		role;

	// Valid for requests
	enum ev_methods		method;
	unsigned char*		custom_method;
	struct cookie*		cookies;
	unsigned char*		host;
	unsigned char*		useragent;

	// Valid for responses
	unsigned char		status_code[4];
	int					status_numeric;
	struct set_cookie*	set_cookies;

	// Valid for both requests and responses
	ssize_t				content_length;
	struct headers		headers;
	struct obstack		meta;			// Storage for metadata, not accessed directly
	unsigned char*		http_ver;
	enum body_len		body_len;		// How to determine the message body length
	unsigned char*		body;
	size_t				body_avail;		// How many bytes are allocated at *body
	size_t				body_size;		// How many bytes are valid at *body
	enum body_storage	body_storage;
	int					body_fd;		// tmpfile fd if body_storage == BODY_STORAGE_MMAP
	ssize_t				chunk_remain;

	// Lexer state
	unsigned char*		cur;
	unsigned char*		mar;
	unsigned char*		tok;
	unsigned char*		lim;
	int					cond;
	int					state;
	enum con_status		status;
	struct mtagpool		mtp;
	/*!stags:re2c:http format = "\tunsigned char*\t\t@@{tag};\n"; */
	/*!mtags:re2c:http format = "\tstruct mtag\t\t\t\t*@@{tag};\n"; */
	size_t				buf_size;
	unsigned char*		buf;
	unsigned char		static_buf[];
};
#define CON_READ_BUF_LEN	CON_STATE_SIZE - sizeof(struct con_state) - 1	// -1: ensure a sentinel at the end of buf

enum aio_action {
	AIO_DONE_CLOSE,		// Close the socket when the io completes
	AIO_DONE_NOTIFY,
	AIO_DONE_IGNORE
};

struct aio_done_action {
	struct ev_io*	con_watch;
	enum aio_action	action;

};

static int push_te(struct con_state* c, enum te_types type) //<<<
{
	/* Check overflow */
	if (c->te_top >= TE_MAX) return 1;

	/* Reject duplicates */
	for (int i=0; i<c->te_top; i++)
		if (c->te[i] == type)
			return 2;

	c->te[c->te_top++] = type;

	return 0;
}

//>>>
static int push_te_accept(struct con_state* c, const unsigned char* r1, const unsigned char* r2, enum te_types type) //<<<
{
	/* Check overflow */
	if (c->te_accept_top >= TE_MAX) return 1;

	/* Reject duplicates */
	for (int i=0; i<c->te_accept_top; i++)
		if (c->te_accept[i].type == type)
			return 2;

	if (r1 && r2) {
		float	rank = 0;
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

		c->te_accept[c->te_accept_top].rank = rank;
	} else {
		c->te_accept[c->te_accept_top].rank = 1.0;
	}

	c->te_accept[c->te_accept_top++].type = type;

	return 0;
}

//>>>

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
static void* thread_start(void* cdata) //<<<
{
	struct timespec after;
	double delta;
	clock_gettime(CLOCK_MONOTONIC, &after);
	delta = after.tv_sec - before.tv_sec + (after.tv_nsec - before.tv_nsec)/1e9 - empty;
	fprintf(stderr, "io_thread start latency: %.1f microseconds\n", delta*1e6);

	io_thread_loop = ev_loop_new(EVFLAG_AUTO);
	if (io_thread_loop == NULL) {
		fprintf(stderr, "Could not initialize thread loop\n");
		return NULL;
	}

	printf("In thread %ld\n", pthread_self());

	ev_async_init(&io_thread_wakeup, io_thread_wakeup_cb);
	ev_async_start(io_thread_loop, &io_thread_wakeup);

	ev_run(io_thread_loop, 0);
	ev_loop_destroy(io_thread_loop);

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
static void lowercase(unsigned char* str) //<<<
{
	unsigned char*	p = NULL;

	for (p=str; *p; p++)
		if (*p >= 'A' && *p <= 'Z')
			*p |= 1<<5;		// Lowercase
}

//>>>
static enum con_status parse_http_message(struct con_state* c) //<<<
{
	unsigned int		yych, yyaccept;
    const unsigned char *h1, *h2, *h3, *h4, *m1, *m2, *v1, *v2, *v3, *v4, *r1, *r2, *st1, *l1, *l2, *l3, *l4, *l5, *l6;
	struct mtag			*f1, *f2, *p1, *p2, *p3, *p4;

	/*!getstate:re2c:http*/
loop:
	c->tok = c->cur;
	/*!re2c:http
		!use:common;
		re2c:eof						= 0;
		re2c:flags:tags					= 1;
		re2c:flags:case-insensitive		= 1;
		re2c:tags:expression			= "c->@@";
		re2c:define:YYCTYPE				= "unsigned char";
		re2c:define:YYCURSOR			= "c->cur";
		re2c:define:YYMARKER			= "c->mar";
		re2c:define:YYLIMIT				= "c->lim";
		re2c:define:YYGETSTATE			= "c->state";
		re2c:define:YYSETSTATE			= "c->state = @@;";
		re2c:define:YYFILL				= "return CON_STATUS_WAITING;";
		re2c:define:YYGETCONDITION		= "c->cond";
		re2c:define:YYSETCONDITION		= "c->cond = @@;";
		re2c:define:YYMTAGP				= "mtag(&@@{tag}, c->tok, c->cur, &c->mtp);";
		re2c:define:YYMTAGN				= "mtag(&@@{tag}, c->tok, NULL, &c->mtp);";

		!use:http_common;

		<statusline> status_line	=> header {
			memcpy(c->status_code, st1, 3);
			c->status_numeric =
				(st1[0] - '0') * 100 +
				(st1[1] - '0') * 10 +
				(st1[2] - '0');

			c->http_ver = obstack_copy0(&c->meta, v1, (int)(v2-v1));
			c->status_code[3] = 0;
		}

		<reqline> crlf	:=> reqline		// RFC7230 3.5
		<reqline>     'GET'		rws	=> reqline_target	{ c->method = METHOD_GET;		goto yyc_reqline_target; }
		<reqline>     'HEAD'	rws	=> reqline_target	{ c->method = METHOD_HEAD;		goto yyc_reqline_target; }
		<reqline>     'POST'	rws	=> reqline_target	{ c->method = METHOD_POST;		goto yyc_reqline_target; }
		<reqline>     'PUT'		rws	=> reqline_target	{ c->method = METHOD_PUT;		goto yyc_reqline_target; }
		<reqline>     'DELETE'	rws	=> reqline_target	{ c->method = METHOD_DELETE;	goto yyc_reqline_target; }
		<reqline>     'CONNECT'	rws	=> reqline_target	{ c->method = METHOD_CONNECT;	goto yyc_reqline_target; }
		<reqline>     'OPTIONS'	rws	=> reqline_target	{ c->method = METHOD_OPTIONS;	goto yyc_reqline_target; }
		<reqline>     'TRACE'	rws	=> reqline_target	{ c->method = METHOD_TRACE;		goto yyc_reqline_target; }
		<reqline> @m1 method @m2 rws => reqline_target	{ c->custom_method = obstack_copy0(&c->meta, m1, (int)(m2-m1));	goto yyc_reqline_target; }

		<reqline_target> @l1 request_target @l2 rws @v3 http_version @v4 crlf	=> header {
			printf("method: target: (%.*s), ver: (%.*s)\n",
					(int)(l2 - l1), l1,
					(int)(v4 - v3), v3);

			goto yyc_header;
		}


		<header,trailer> header_field_folded crlf	{
			// Overwrite all obs_fold with equivalent number of sp chars and reparse
			printf("header (folded): (%.*s) => (%.*s)\n",
					(int)(h2 - h1), h1,
					(int)(h4 - h3), h3);

			struct mtag*	start	= f1;
			struct mtag*	end		= f2;

			while (start && end) {
				memset(c->tok + start->dist, ' ', end->dist - start->dist);
				start = start->prev;
				end = end->prev;
			}

			c->cur = c->tok;
			c->mar = c->tok;
			goto loop;
		}

		trailer_forbidden
			= "Content-Type"
			| "Transfer-Encoding"
			| "Host"
			| "If-" field_name
			| "WWW-Authenticate"
			| "Authorization"
			| "Proxy-Authenticate"
			| "Proxy-Authorization"
			| "Cookie"
			| "Set-Cookie"
			| "Age"
			| "Cache-Control"
			| "Expires"
			| "Date"
			| "Location"
			| "Retry-After"
			| "Vary"
			| "Warning"
			| "Content-Encoding"
			| "Content-Type"
			| "Content-Range"
			| "Trailer";

		<trailer> trailer_forbidden ':' ows field_value ows crlf	:=> trailer

		<header> "Content-Length" ':' ows		:=> contentlength
		<contentlength>	@l1 digit+ @l2 ows crlf	=> header {
			ssize_t					content_length = 0;
			const unsigned char*	digit = l1;

			printf("content-length: (%.*s)\n",
					(int)(l2 - l1), l1);

			while (digit < l2) {
				content_length *= 10;
				content_length += *digit++ - '0';
				if (content_length < 0) return CON_STATUS_ERROR; // Overflow
			}

			printf("Decoded content-length: %ld\n", content_length);

			// Invalid to have multiple Content-Length headers with different values
			if (
					c->content_length != -1 &&
					c->content_length != content_length
			) {
				if (c->role == CON_ROLE_SERVER) {
					// TODO: MUST close with 400 Bad Request
				} else {
					// TODO: MUST close the connection and discard this message
				}
				return CON_STATUS_ERROR;
			}

			c->content_length = content_length;
			goto loop;
		}

		<header> "Transfer-Encoding:" ows (',' ows)*	:=> te
		<te> ows       "chunked"  ows / (',' | crlf)	{ if (push_te(c, TE_CHUNKED))	return CON_STATUS_ERROR; goto yyc_te; }
		<te> ows "x-"? "compress" ows / (',' | crlf)	{ if (push_te(c, TE_COMPRESS))	return CON_STATUS_ERROR; goto yyc_te; }
		<te> ows       "deflate"  ows / (',' | crlf)	{ if (push_te(c, TE_DEFLATE))	return CON_STATUS_ERROR; goto yyc_te; }
		<te> ows "x-"? "gzip"     ows / (',' | crlf)	{ if (push_te(c, TE_GZIP))		return CON_STATUS_ERROR; goto yyc_te; }
		<te> ows       "identity" ows / (',' | crlf)	{ goto yyc_te; }
		<te> crlf							=> header	{ goto loop; }
		<te> *											{ fprintf(stderr, "Unsupported Transfer-Encoding\n"); return CON_STATUS_ERROR; }

		<header> "TE:" ows (',' ows)*	:=> te_accept
		<te_accept> ows       "trailers"            ows / (',' | crlf)		{ if (push_te_accept(c, r1, r2, TE_TRAILERS))	return CON_STATUS_ERROR; goto yyc_te_accept; }
		<te_accept> ows "x-"? "compress" t_ranking? ows / (',' | crlf)		{ if (push_te_accept(c, r1, r2, TE_COMPRESS))	return CON_STATUS_ERROR; goto yyc_te_accept; }
		<te_accept> ows       "deflate"  t_ranking? ows / (',' | crlf)		{ if (push_te_accept(c, r1, r2, TE_DEFLATE))	return CON_STATUS_ERROR; goto yyc_te_accept; }
		<te_accept> ows "x-"? "gzip"     t_ranking? ows / (',' | crlf)		{ if (push_te_accept(c, r1, r2, TE_GZIP))		return CON_STATUS_ERROR; goto yyc_te_accept; }
		<te_accept> ows token (ows ';' ows transfer_parameter)*				{ goto yyc_te_accept; }
		<te_accept> crlf										=> header	{ goto loop; }
		<te_accept> *														{ fprintf(stderr, "Unsupported Transfer-Encoding\n"); return CON_STATUS_ERROR; }

		extension_av		= [\x20-\x7E] \ ';';
		path_value			= [\x20-\x7E] \ ';';
		domain_value		= (alpha | digit) (alpha | digit | '-')*;
		non_zero_digit		= [1-9];
		b24					= '2' [0-3] | [01] [0-9];
		b60					= [0-5] [0-9];
		time				= b24 ':' b60 ':' b60;
		month				= "Jan" | "Feb" | "Mar" | "Apr" | "May" | "Jun" | "Jul" | "Aug" | "Sep" | "Oct" | "Nov" | "Dec";
		date1				= digit{2} sp month sp digit{4};
		wkday				= "Mon" | "Tue" | "Wed" | "Thu" | "Fri" | "Sat" | "Sun";
		sane_cookie_date	= wkday ',' sp date1 sp time sp "GMT";
		cookie_av_end		= (';' | ows crlf);
		cookie_octets		= ([\x20-\x7E] \ [ ",;\x5C])*;
		cookie_value		= @l3 cookie_octets @l4 | '"' @l5 cookie_octets @l6 '"';
		cookie_name			= token;
		cookie_pair			= @l1 cookie_name @l2 '=' cookie_value;
		cookie_string		= cookie_pair (';' sp cookie_pair)*;

		<header> "Set-Cookie:" ows cookie_pair => cookie_av {
			struct set_cookie*	cookie = obstack_alloc(&c->meta, sizeof *cookie);
			cookie->name  = obstack_copy0(&c->meta, l1, (int)(l2-l1));
			if (l3) {
				cookie->value = obstack_copy0(&c->meta, l3, (int)(l3-l4));
			} else {
				cookie->value = obstack_copy0(&c->meta, l5, (int)(l6-l5));
			}
			cookie->next = c->set_cookies;
			c->set_cookies = cookie;
			goto yyc_cookie_av;
		}
		<cookie_av> "Expires="	@l1 sane_cookie_date @l2		/ cookie_av_end => cookie_av_end { c->set_cookies->expires	= obstack_copy0(&c->meta, l1, (int)(l2-l1));	goto yyc_cookie_av_end; }
		<cookie_av> "Domain="	@l1 domain_value @l2			/ cookie_av_end => cookie_av_end { c->set_cookies->domain	= obstack_copy0(&c->meta, l1, (int)(l2-l1));	goto yyc_cookie_av_end; }
		<cookie_av> "Path="		@l1 path_value @l2				/ cookie_av_end => cookie_av_end { c->set_cookies->path		= obstack_copy0(&c->meta, l1, (int)(l2-l1));	goto yyc_cookie_av_end; }
		<cookie_av> "HttpOnly"									/ cookie_av_end	=> cookie_av_end { c->set_cookies->flags	|= COOKIE_FLAG_HTTPONLY;						goto yyc_cookie_av_end; }
		<cookie_av> "Secure"									/ cookie_av_end	=> cookie_av_end { c->set_cookies->flags	|= COOKIE_FLAG_SECURE;							goto yyc_cookie_av_end; }
		<cookie_av> "Max-Age="	@l1 non_zero_digit digit* @l2	/ cookie_av_end => cookie_av_end {
			int64_t		acc = 0;
			for (unsigned const char* d=l1; d<l2; d++) {
				acc *= 10;
				acc += *d - '0';
				if (acc < 0) return CON_STATUS_ERROR;	// Overflow
			}
			c->set_cookies->max_age = acc;
			goto yyc_cookie_av_end;
		}
		<cookie_av> @l1 extension_av @l2						/ cookie_av_end	=> cookie_av_end { 																			goto yyc_cookie_av_end; }
		<cookie_av_end> ';'			:=> cookie_av
		<cookie_av_end> ows crlf	=> header		{ goto loop; }

		<header> "Cookie:" ows		:=> cookie
		<cookie> cookie_pair / (';'	| ows crlf)		=> cookie_end {
			struct cookie*		cookie = obstack_alloc(&c->meta, sizeof *cookie);
			cookie->name  = obstack_copy0(&c->meta, l1, (int)(l2-l1));
			cookie->value = obstack_copy0(&c->meta, l3, (int)(l4-l3));
			cookie->next = c->cookies;
			c->cookies = cookie;
			goto yyc_cookie_end;
		}
		<cookie_end> ';' ows	:=> cookie
		<cookie_end> ows crlf	=> header		{ goto loop; }

		<header> "Connection:" ows token (ows ',' ows token)* ows crlf {
			// TODO: handle these, particularly "close", "keep-alive" and "upgrade"
			goto loop;
		}

		protocol_version	= token;
		protocol_name		= token;
		protocol			= protocol_name ('/' protocol_version)?;

		<header> "Upgrade:" ows protocol (ows ',' ows protocol)* ows crlf {
			// TODO
			goto loop;
		}

		<header> "Host:" ows @l1 host (':' port)? @l2 ows crlf		{ c->host			= obstack_copy0(&c->meta, l1, (int)(l2-l1));	goto loop; }
		<header> "User-Agent:" ows @l1 field_value @l2 ows crlf		{ c->useragent		= obstack_copy0(&c->meta, l1, (int)(l2-l1));	goto loop; }

		<header> "Content-Type:" ows media_type ows crlf	{
			if (c->contenttype) return CON_STATUS_ERROR;
			c->contenttype	= obstack_copy0(&c->meta, l1, (int)(l2-l1));
			lowercase(c->contenttype);

			struct mtag	*pname1 = p1, *pname2 = p2, *pval1 = p3, *pval2 = p4;
			while (0 && pname1) {
				struct mediatype_param*	param = obstack_alloc(&c->meta, sizeof *param);

				param->name = obstack_copy0(&c->meta, c->tok + pname1->dist, pname2->dist - pname1->dist);
				if (*(c->tok + pval1->dist) == '"') {
					pval1->dist++;
					pval2->dist--;
					const unsigned char*const l = c->tok + pval2->dist;
					for (unsigned char* p=c->tok + pval1->dist; p<l; p++) {
						if (*p == '\\') p++;	// lex rules ensure this can't run off the end
						obstack_1grow(&c->meta, *p);
					}
					obstack_1grow(&c->meta, 0);
					param->value = obstack_finish(&c->meta);
				} else {
					param->value = obstack_copy0(&c->meta, c->tok + pval1->dist, pval2->dist - pval1->dist);
				}
				lowercase(param->name);
				lowercase(param->value);
				param->next = c->contenttype_params;
				c->contenttype_params = param;
				pname1 = pname1->prev;
				pname2 = pname2->prev;
				pval1 = pval1->prev;
				pval2 = pval2->prev;
			}
			goto loop;
		}

		<header>  @h1 field_name @h2 ':' :=> header_field_value
		<trailer> @h1 field_name @h2 ':' :=> trailer_field_value
		<header_field_value> ows @h3 field_value @h4 ows crlf	=> header {
			struct header	hdr = {
				.field_name  = obstack_copy0(&c->meta, h1, (int)(h2-h1)),
				.field_value = obstack_copy0(&c->meta, h3, (int)(h4-h3))
			};
			obstack_grow(&c->headers_storage, &hdr, sizeof hdr);
			c->header_count++;

			printf("header: (%.*s) => (%.*s)\n",
					(int)(h2 - h1), h1,
					(int)(h4 - h3), h3);

			goto loop;
		}
		<trailer_field_value> ows @h3 field_value @h4 ows crlf	=> trailer {
			struct header	hdr = {
				.field_name  = obstack_copy0(&c->meta, h1, (int)(h2-h1)),
				.field_value = obstack_copy0(&c->meta, h3, (int)(h4-h3))
			};
			obstack_grow(&c->headers_storage, &hdr, sizeof hdr);
			c->header_count++;

			printf("header: (%.*s) => (%.*s)\n",
					(int)(h2 - h1), h1,
					(int)(h4 - h3), h3);

			goto loop;
		}

		<header> crlf	{ mtagpool_clear(&c->mtp, c); return CON_STATUS_BODY; }


		chunksize		= hexdigit+;
		chunk_ext_name	= token;
		chunk_ext_value	= token | quoted_string;
		chunk_ext		= ';' #p1 chunk_ext_name #p2 ( '=' chunk_ext_value )? #p3;

		<chunk> '0'+ chunk_ext* crlf				:=> trailer
		<chunk> @l1 chunksize @l2 chunk_ext* crlf	=> chunk_bytes {
			ssize_t					chunklen = 0;
			const unsigned char*	p = l1;

			// Decode hex chunk length <<<
			while (p < l2) {
				const int	ch = *p++;
				chunklen *= 16;
				if (ch > 'a')		chunklen += ch - 'a';
				else if (ch > 'A')	chunklen += ch - 'A';
				else				chunklen += ch - '0';

				if (chunklen < 0) return CON_STATUS_ERROR; // Overflow
			}
			// Decode hex chunk length >>>

			printf("Read chunk length: %ld\n", chunklen);

			struct mtag	*lp1 = p1, *lp2 = p2, *lp3 = p3;
			while (lp1) {
				if (lp3->dist > lp2->dist) {
					printf("\tIngoring chunk ext: (%.*s): (%.*s)\n",
							(int)(lp2->dist - lp1->dist),     c->tok + lp1->dist,
							(int)(lp3->dist - lp2->dist - 1), c->tok + lp2->dist + 1);
				} else {
					printf("\tIngoring chunk ext: (%.*s)\n",
							(int)(lp2->dist - lp1->dist), c->tok + lp1->dist);
				}
				lp1 = lp1->prev;
				lp2 = lp2->prev;
				lp3 = lp3->prev;
			}

			c->chunk_remain = chunklen;

			// Grow the body allocation if needed <<<
			if (c->body_avail <= c->body_size + chunklen) {
				switch (c->body_storage) {
					case BODY_STORAGE_OBSTACK:
						{
							obstack_blank(&c->meta, chunklen);
							c->body = obstack_base(&c->meta);
							c->body_avail = obstack_object_size(&c->meta) + obstack_room(&c->meta);
						}
						break;
					case BODY_STORAGE_MMAP:
						{
							const size_t	new_size = c->body_size + chunklen;

							if (-1 == ftruncate(c->body_fd, new_size)) {
								perror("Error calling ftruncate to expand the body tmpfile");
								return CON_STATUS_ERROR;
							}

							void*	new = mremap(c->body, c->body_avail, new_size, MREMAP_MAYMOVE);

							if (new == MAP_FAILED) {
								perror("Error growing body mmap");
								return CON_STATUS_ERROR;
							}
							c->body = new;
							c->body_avail = new_size;
						}
						break;
					default:
						fprintf(stderr, "Invalid body_storage: %d\n", c->body_storage);
						return CON_STATUS_ERROR;
				}
			}
			// Grow the body allocation if needed >>>

			goto yyc_chunk_bytes;
		}
		<chunk_bytes> @l1 [\x00-\xff] {
			c->chunk_remain--;

			c->body[c->body_size++] = *l1;

			if (c->chunk_remain <= 0) {
				c->cond = yycchunk_end;
				goto yyc_chunk_end;
			}
		}
		<chunk_end> crlf	:=> chunk
		<trailer> crlf	{ return CON_STATUS_BODY_DONE; }

		<*> $			{ return CON_STATUS_ERROR; }
		<*> *			{ return CON_STATUS_ERROR; }
	*/
}

//>>>
void respond(struct con_status* c, int status, 
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-label"	// --storable-state causes labels to be generated for yyfill states but this block doesn't use them
void report(const char* type, const unsigned char* chunk) //<<<
{
	unsigned char			yych;
	const unsigned char*	s = chunk;
	const unsigned char*	tok;

	printf("%s: \"", type);

loop:
	tok = s;
	/*!local:re2c:report
	!use:basic;

	cr			= "\r";
	lf			= "\n";
	tab			= "\t";
	del			= "\x7F";
	C0			= [\x01-\x1F];
	printable	= [\x01-\x7E\x80-\xFF] \ C0;

	end			{ printf("\" (%d bytes)\n", (int)(s-1-chunk));					return; }

	printable+	{ printf("%.*s", (int)(s-tok), tok);	goto loop; }
	cr			{ printf("\\r");						goto loop; }
	lf			{ printf("\\n");						goto loop; }
	tab			{ printf("\\t");						goto loop; }
	.			{ printf("\\x%02x", *(s-1));			goto loop; }

	*			{ fprintf(stderr, "Error attempting to report chunk send\n");	return; }

	*/
}

//>>>
#pragma GCC diagnostic pop
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
					remain = c->content_length - c->body_size;
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
						obstack_blank(&c->meta, remain);
						c->body = obstack_base(&c->meta);
						c->body_avail = obstack_object_size(&c->meta) + obstack_room(&c->meta);

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
				report("shifting to", c->tok);
				memmove(c->buf, c->tok, c->buf_size - shift);
				c->lim -= shift;
				c->cur -= shift;
				c->mar -= shift;
				c->tok -= shift;
				/*!stags:re2c:http format = "\t\t\tif (c->@@) c->@@ -= shift;\n"; */
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

			printf("read: %ld bytes\n", got);
			switch ((c->status = parse_http_message(c))) {
				case CON_STATUS_WAITING:
					printf("parse_con_req returned CON_STATUS_WAITING\n");
					// Loop back around in case the fd has more to give us
					goto loop;;

				case CON_STATUS_BODY:
					/* Instead of incrementing c->header_count as we add them, we could do it here: */
					// c->header_count = obstack_size(&c->headers_storage) / sizeof(struct header);
					c->headers = obstack_finish(&c->headers_storage);
					printf("Got headers, read body\n");

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
					} else if (c->te_top) { // Transfer-Encoding present
						if (c->content_length != -1)
							c->content_length = -1;	// MUST strip content_length if it was present

						if (c->te[c->te_top] == TE_CHUNKED) {
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
					} else if (c->content_length > -1) {
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
							if (c->content_length == 0)
								goto message_complete;

							if (have >= c->content_length) {
								// We already have the complete body
								c->body_storage = BODY_STORAGE_BORROWED;
								c->body = c->cur;
								c->body_size = c->content_length;
								c->cur += c->content_length;
								c->tok = c->mar = c->cur;
								goto message_complete;
							}

							const int room = obstack_room(&c->meta);
							if (room >= c->content_length) {
								// There is room available on the obstack, move what we have there
								c->body_storage = BODY_STORAGE_OBSTACK;
								obstack_grow(&c->meta, c->cur, have);
								c->body = obstack_base(&c->meta);
								c->body_avail = have + obstack_room(&c->meta);
								c->body_size = have;
							} else {
								// Create a memory mapped unlinked tmpfile
								int		rc;
								c->body_storage = BODY_STORAGE_MMAP;
								c->body_fd = open(".", O_TMPFILE | O_RDWR, S_IRUSR | S_IWUSR);
								rc = ftruncate(c->body_fd, c->content_length);
								if (rc == -1) {
									perror("Could not expand body tmpfile");
									goto close_500;
								}
								c->body = mmap(NULL, c->content_length, PROT_READ | PROT_WRITE, MAP_SHARED, c->body_fd, 0);
								if (c->body == MAP_FAILED) {
									perror("Could not mmap body tmpfile");
									goto close_500;
								}
								c->body_avail = c->content_length;

								memcpy(c->body, c->cur, have);
								c->body_size = have;
								// Keep c->body_fd open in case we want to save this message body to a file later (just link the file)
							}
							c->cur = c->tok = c->mar = c->lim;
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
							obstack_grow(&c->meta, c->cur, have);
							c->body = obstack_base(&c->meta);
							c->body_size = have;
							c->body_avail = have + obstack_room(&c->meta);
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
						obstack_chunk_size(&c->meta) = 1048576;  // TODO: tune this
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
	if (c->buf != c->static_buf) {
		free(c->buf);
		c->buf = c->static_buf;
	}
	c->headers = NULL;
	c->headers_tail = NULL;
	for (int i=0; i<HDR_OTHER; i++) {
		c->first_header[i]	= NULL;
		c->last_header[i]	= NULL;
	}
	obstack_free(&c->meta, NULL);
	free(w->data);
	w->data = NULL;
	free(w);
	w = NULL;
	return;

close_400:
	// TODO: Respond with 400 Bad Request and close
	return;

close_500:
	// TODO: Respond with 500 Bad Request and close
	return;

	

message_complete:
	if (w) {
		ev_io_stop(loop, w);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wparentheses"
		ev_io_modify(w, 0);		// Disable callbacks for this fd while the message is processed
#pragma GCC diagnostic pop
	}
	printf("Message complete\n");
	// TODO: dispatch callback for message
	return;
}

//>>>
void accept_cb(struct ev_loop* loop, struct ev_io* w, int revents) //<<<
{
	int							con_fd;
	struct sockaddr_storage		con_addr;
	struct ev_io*				con_watch = NULL;
	struct con_state*			c;
	socklen_t					addrlen = sizeof con_addr;

	printf("Got accept_cb in thread %ld\n", pthread_self());

	con_fd = accept(w->fd, (struct sockaddr*)&con_addr, &addrlen);
	if (con_fd == -1) {
		perror("Could not accept new connection");
		exit(EXIT_FAILURE);
	}

	if (
			-1 == fcntl(con_fd, F_SETFD, FD_CLOEXEC) ||
			-1 == fcntl(con_fd, F_SETFL, O_NONBLOCK)
	) {
		perror("Could not set FD_CLOEXEC and O_NONBLOCK on con_fd");
		exit(EXIT_FAILURE);
	}

	c = malloc(CON_STATE_SIZE);
	c->buf = c->static_buf;
	c->cur = c->mar = c->tok = c->lim = c->buf + CON_READ_BUF_LEN;
	c->lim[0]			= 0;	// sentinel
	c->state			= -1;
	c->status			= CON_STATUS_WAITING;
	c->cond				= yycreqline;
	c->status_code[0]	= 0;
	c->role				= CON_ROLE_SERVER;
	c->method			= METHOD_UNSPECIFIED;
	c->custom_method	= NULL;
	c->buf_size			= CON_READ_BUF_LEN;
	c->http_ver			= NULL;
	c->content_length	= -1;
	/*!stags:re2c:http format = "\tc->@@ = 0;\n"; */
	/*!mtags:re2c:http format = "\tc->@@ = NULL;\n"; */
    mtagpool_init(&c->mtp);
	c->headers			= {0};
	c->set_cookies		= NULL;
	c->cookies			= NULL;
	c->host				= NULL;
	c->useragent		= NULL;
	c->content_type		= NULL;
	c->body_len			= BODY_LEN_NOTSET;
	c->body_size		= 0;
	c->body_avail		= 0;
	c->body				= NULL;
	c->body_storage		= BODY_STORAGE_NONE;
	c->body_fd			= -1;
	c->chunk_remain		= 0;
	obstack_init(&c->meta);

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
