#include "evhttpInt.h"

/*!include:re2c "common.re" */

/*!header:re2c:on */
struct con_state {
	enum con_role		role;

	uint64_t			accept_time;	// The first moment we became aware of the connection (nanoseconds resolution, cputime since process start)

	// Valid for requests
	enum ev_methods		method;
	unsigned char*		custom_method;
	struct cookie*		cookies;

	// Valid for responses
	unsigned char		status_code[4];
	int					status_numeric;
	struct set_cookie*	set_cookies;

	// Valid for both requests and responses
	int					connectionflags;
	struct headers		headers;
	struct obstack*		ob;				// Storage for the life of this message, not accessed directly
	struct obstack*		logs;
	struct log*			logs_head;
	struct log*			logs_tail;
	uint64_t			last_log;
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
	/*!stags:re2c format = "\tunsigned char*\t\t@@{tag};\n"; */
	/*!mtags:re2c format = "\tstruct mtag\t\t\t*@@{tag};\n"; */
	size_t				buf_size;
	unsigned char*		buf;
};

void shift_msg_buffer(struct con_state* c, size_t shift);
void init_msg_buffer(struct con_state* c);
enum con_status parse_http_message(struct con_state* c);
/*!header:re2c:off */

enum con_status parse_http_message(struct con_state* c) //<<<
{
	unsigned int		yych, yyaccept;
    const unsigned char *h1, *h2, *h3, *h4, *m1, *m2, *v1, *v2, *r1, *r2, *st1, *l1, *l2, *l3, *l4, *l5, *l6, *end;
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
		re2c:define:YYCONDTYPE			= "msg_cond_type";

		!use:http_common;

		// Status line (client) <<<
		<statusline> status_line	=> header {
			memcpy(c->status_code, st1, 3);
			c->status_numeric =
				(st1[0] - '0') * 100 +
				(st1[1] - '0') * 10 +
				(st1[2] - '0');

			c->http_ver = obstack_copy0(c->ob, v1, (int)(v2-v1));
			c->status_code[3] = 0;
		}
		// Status line (client) >>>
		// Request line (server) <<<
		<reqline> crlf	:=> reqline		// RFC7230 3.5
		<reqline>     'GET'		rws	=> reqline_target	{ c->method = METHOD_GET;		goto yyc_reqline_target; }
		<reqline>     'HEAD'	rws	=> reqline_target	{ c->method = METHOD_HEAD;		goto yyc_reqline_target; }
		<reqline>     'POST'	rws	=> reqline_target	{ c->method = METHOD_POST;		goto yyc_reqline_target; }
		<reqline>     'PUT'		rws	=> reqline_target	{ c->method = METHOD_PUT;		goto yyc_reqline_target; }
		<reqline>     'DELETE'	rws	=> reqline_target	{ c->method = METHOD_DELETE;	goto yyc_reqline_target; }
		<reqline>     'CONNECT'	rws	=> reqline_target	{ c->method = METHOD_CONNECT;	goto yyc_reqline_target; }
		<reqline>     'OPTIONS'	rws	=> reqline_target	{ c->method = METHOD_OPTIONS;	goto yyc_reqline_target; }
		<reqline>     'TRACE'	rws	=> reqline_target	{ c->method = METHOD_TRACE;		goto yyc_reqline_target; }
		<reqline> @m1 method @m2 rws => reqline_target	{ c->custom_method = obstack_copy0(c->ob, m1, (int)(m2-m1));	goto yyc_reqline_target; }

		<reqline_target> @l1 request_target @l2 rws @l3 http_version @l4 crlf	=> header {
#if 0
			printf("method: target: (%.*s), ver: (%.*s)\n",
					(int)(l2 - l1), l1,
					(int)(v4 - v3), v3);
#endif

			goto yyc_header;
		}
		// Request line (server) >>>

		// Unfolding <<<
		<header,trailer> header_field_folded crlf	{
			// Overwrite all obs_fold with equivalent number of sp chars and reparse
#if 0
			printf("header (folded): (%.*s) => (%.*s)\n",
					(int)(h2 - h1), h1,
					(int)(h4 - h3), h3);
#endif

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
		// Unfolding >>>

		// Ignore trailer forbidden headers <<<
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
		// Ignore trailer forbidden headers >>>

		// Content-Length: <<<
		<header> "Content-Length" ':' ows		:=> contentlength
		<contentlength>	@l1 digit+ @l2 ows crlf	=> header {
			ssize_t					content_length = 0;
			const unsigned char*	digit = l1;

#if 0
			printf("content-length: (%.*s)\n", (int)(l2 - l1), l1);
#endif

			while (digit < l2) {
				content_length *= 10;
				content_length += *digit++ - '0';
				if (content_length < 0) return CON_STATUS_ERROR; // Overflow
			}

#if 0
			printf("Decoded content-length: %ld\n", content_length);
#endif

			// Invalid to have multiple Content-Length headers with different values
			if (
					c->headers.first[HDR_CONTENT_LENGTH] != NULL &&
					c->headers.first[HDR_CONTENT_LENGTH]->field_value.integer != content_length
			) {
				if (c->role == CON_ROLE_SERVER) {
					// TODO: MUST close with 400 Bad Request
				} else {
					// TODO: MUST close the connection and discard this message
				}
				return CON_STATUS_ERROR;
			}

			struct header* h = new_header(c->ob);
			h->field_name = HDR_CONTENT_LENGTH;
			h->field_value.integer = content_length;
			append_header(&c->headers, h);

			goto loop;
		}
		// Content-Length: >>>
		// Transfer-Encoding: <<<
		<header> "Transfer-Encoding:" ows (',' ows)*	:=> te
		<te> ows       "chunked"  ows / (',' | crlf)	{ if (push_te(c, TE_CHUNKED))	return CON_STATUS_ERROR; goto yyc_te; }
		<te> ows "x-"? "compress" ows / (',' | crlf)	{ if (push_te(c, TE_COMPRESS))	return CON_STATUS_ERROR; goto yyc_te; }
		<te> ows       "deflate"  ows / (',' | crlf)	{ if (push_te(c, TE_DEFLATE))	return CON_STATUS_ERROR; goto yyc_te; }
		<te> ows "x-"? "gzip"     ows / (',' | crlf)	{ if (push_te(c, TE_GZIP))		return CON_STATUS_ERROR; goto yyc_te; }
		<te> ows       "identity" ows / (',' | crlf)	{ goto yyc_te; }
		<te> crlf							=> header	{ goto loop; }
		<te> *											{ fprintf(stderr, "Unsupported Transfer-Encoding\n"); return CON_STATUS_ERROR; }
		// Transfer-Encoding: >>>
		// TE: <<<
		<header> "TE:" ows (',' ows)*	:=> te_accept
		<te_accept> ows       "trailers"            ows / (',' | crlf)		{ if (push_te_accept(c, r1, r2, TE_TRAILERS))	return CON_STATUS_ERROR; goto yyc_te_accept; }
		<te_accept> ows "x-"? "compress" t_ranking? ows / (',' | crlf)		{ if (push_te_accept(c, r1, r2, TE_COMPRESS))	return CON_STATUS_ERROR; goto yyc_te_accept; }
		<te_accept> ows       "deflate"  t_ranking? ows / (',' | crlf)		{ if (push_te_accept(c, r1, r2, TE_DEFLATE))	return CON_STATUS_ERROR; goto yyc_te_accept; }
		<te_accept> ows "x-"? "gzip"     t_ranking? ows / (',' | crlf)		{ if (push_te_accept(c, r1, r2, TE_GZIP))		return CON_STATUS_ERROR; goto yyc_te_accept; }
		<te_accept> ows token (ows ';' ows transfer_parameter)*				{ goto yyc_te_accept; }
		<te_accept> crlf										=> header	{ goto loop; }
		<te_accept> *														{ fprintf(stderr, "Unsupported Transfer-Encoding\n"); return CON_STATUS_ERROR; }
		// TE: >>>
		// Set-Cookie: <<<
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
			struct set_cookie*	cookie = obstack_alloc(c->ob, sizeof *cookie);
			cookie->name  = obstack_copy0(c->ob, l1, (int)(l2-l1));
			if (l3) {
				cookie->value = obstack_copy0(c->ob, l3, (int)(l3-l4));
			} else {
				cookie->value = obstack_copy0(c->ob, l5, (int)(l6-l5));
			}
			cookie->next = c->set_cookies;
			c->set_cookies = cookie;
			goto yyc_cookie_av;
		}
		<cookie_av> "Expires="	@l1 sane_cookie_date @l2		/ cookie_av_end => cookie_av_end { c->set_cookies->expires	= obstack_copy0(c->ob, l1, (int)(l2-l1));	goto yyc_cookie_av_end; }
		<cookie_av> "Domain="	@l1 domain_value @l2			/ cookie_av_end => cookie_av_end { c->set_cookies->domain	= obstack_copy0(c->ob, l1, (int)(l2-l1));	goto yyc_cookie_av_end; }
		<cookie_av> "Path="		@l1 path_value @l2				/ cookie_av_end => cookie_av_end { c->set_cookies->path		= obstack_copy0(c->ob, l1, (int)(l2-l1));	goto yyc_cookie_av_end; }
		<cookie_av> "HttpOnly"									/ cookie_av_end	=> cookie_av_end { c->set_cookies->flags	|= COOKIE_FLAG_HTTPONLY;					goto yyc_cookie_av_end; }
		<cookie_av> "Secure"									/ cookie_av_end	=> cookie_av_end { c->set_cookies->flags	|= COOKIE_FLAG_SECURE;						goto yyc_cookie_av_end; }
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
		<cookie_av> @l1 extension_av @l2						/ cookie_av_end	=> cookie_av_end { 																		goto yyc_cookie_av_end; }
		<cookie_av_end> ';'			:=> cookie_av
		<cookie_av_end> ows crlf	=> header		{ goto loop; }
		// Set-Cookie: >>>
		// Cookie: <<<
		<header> "Cookie:" ows		:=> cookie
		<cookie> cookie_pair / (';'	| ows crlf)		=> cookie_end {
			struct cookie*		cookie = obstack_alloc(c->ob, sizeof *cookie);
			cookie->name  = obstack_copy0(c->ob, l1, (int)(l2-l1));
			cookie->value = obstack_copy0(c->ob, l3, (int)(l4-l3));
			cookie->next = c->cookies;
			c->cookies = cookie;
			goto yyc_cookie_end;
		}
		<cookie_end> ';' ows	:=> cookie
		<cookie_end> ows crlf	=> header		{ goto loop; }
		// Cookie: >>>
		// Connection: <<<
		connectiontoken = @l1
			( @l2 "close"
			| @l3 "keep-alive"
			| @l4 "upgrade"
			| @l5 token ) @l6;

		<header> "Connection:"	:=> connection
		<connection> ows connectiontoken ows @end (crlf | ',') {
			     if (l2)	c->connectionflags |= CON_CLOSE;
			else if (l3)	c->connectionflags |= CON_KEEP_ALIVE;
			else if (l4)	c->connectionflags |= CON_UPGRADE;

			struct header* h = new_header(c->ob);
			h->field_name = HDR_CONNECTION;
			h->field_value.str = obstack_copy0(c->ob, l1, (int)(l6-l1));
			append_header(&c->headers, h);

			if (*end == ',')	goto yyc_connection;
				else			goto loop;
		}
		// Connection: >>>
		// Upgrade: <<<
		protocol_version	= token;
		protocol_name		= token;
		protocol			= protocol_name ('/' protocol_version)?;

		<header> "Upgrade:" ows protocol (ows ',' ows protocol)* ows crlf {
			// TODO
			goto loop;
		}
		// Upgrade: >>>
		// Content-Type: <<<
		<header> "Content-Type:" ows media_type ows crlf	{
			if (c->headers.first[HDR_CONTENT_TYPE]) return CON_STATUS_ERROR;
			struct media_type*	content_type = obstack_alloc(c->ob, sizeof *content_type);
			content_type->media_type = obstack_copy0(c->ob, l1, (int)(l2-l1));
			lowercase(content_type->media_type);

			struct mtag	*pname1 = p1, *pname2 = p2, *pval1 = p3, *pval2 = p4;
			while (0 && pname1) {
				struct media_type_param*	param = obstack_alloc(c->ob, sizeof *param);

				param->name = obstack_copy0(c->ob, c->tok + pname1->dist, pname2->dist - pname1->dist);
				if (*(c->tok + pval1->dist) == '"') {
					pval1->dist++;
					pval2->dist--;
					const unsigned char*const l = c->tok + pval2->dist;
					for (unsigned char* p=c->tok + pval1->dist; p<l; p++) {
						if (*p == '\\') p++;	// lex rules ensure this can't run off the end
						obstack_1grow(c->ob, *p);
					}
					obstack_1grow(c->ob, 0);
					param->value = obstack_finish(c->ob);
				} else {
					param->value = obstack_copy0(c->ob, c->tok + pval1->dist, pval2->dist - pval1->dist);
				}
				lowercase(param->name);
				lowercase(param->value);
				param->next = content_type->params;
				content_type->params = param;
				pname1 = pname1->prev;
				pname2 = pname2->prev;
				pval1 = pval1->prev;
				pval2 = pval2->prev;
			}
			goto loop;
		}
		// Content-Type: >>>
		// Host: <<<
		<header> "Host:" :=> host
		<host> ows @l1 host (':' port)? @l2 ows crlf	=> header {
			if (c->headers.first[HDR_HOST]) return CON_STATUS_ERROR;
			new_header_str(c, HDR_HOST, l1, (int)(l2-l1));
			goto loop;
		}
		// Host: >>>
		// User-Agent: <<<
		<header> "User-Agent:" ows @l1 field_value @l2 ows crlf		{
			if (c->headers.first[HDR_USER_AGENT]) return CON_STATUS_ERROR;
			new_header_str(c, HDR_USER_AGENT, l1, (int)(l2-l1));
			goto loop;
		}
		// User-Agent: >>>
		// Generic header handling <<<
		<header> @h1 field_name @h2 ':' :=> header_field_value
		<header_field_value> ows @h3 field_value @h4 ows crlf	=> header {
			new_header_other(c, h1, (int)(h2-h1), h3, (int)(h4-h3));
			goto loop;
		}

		<trailer> @h1 field_name @h2 ':' :=> trailer_field_value
		<trailer_field_value> ows @h3 field_value @h4 ows crlf	=> trailer {
			new_header_other(c, h1, (int)(h2-h1), h3, (int)(h4-h3));
			goto loop;
		}
		// Generic header handling >>>

		<header>  crlf	{ mtagpool_clear(&c->mtp, c); return CON_STATUS_BODY; }
		<trailer> crlf	{ return CON_STATUS_BODY_DONE; }


		// Transfer coding chunked <<<
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
							obstack_blank(c->ob, chunklen);
							c->body = obstack_base(c->ob);
							c->body_avail = obstack_object_size(c->ob) + obstack_room(c->ob);
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
		// Transfer coding chunked >>>

		<*> $			{ return CON_STATUS_ERROR; }
		<*> *			{ return CON_STATUS_ERROR; }
	*/
}

//>>>
void shift_msg_buffer(struct con_state* c, size_t shift) //<<<
{
	memmove(c->buf, c->tok, c->buf_size - shift);
	c->lim -= shift;
	c->cur -= shift;
	c->mar -= shift;
	c->tok -= shift;
	/*!stags:re2c:http format = "\t\t\tif (c->@@) c->@@ -= shift;\n"; */
}

//>>>
void init_msg_buffer(struct con_state* c) //<<<
{
	const uint64_t a1 = nanoseconds_process_cpu();
#define BUFSIZE	8192
#if 1
	c->buf = obstack_alloc(c->ob, BUFSIZE);
#else
	c->buf = obstack_base(c->ob);
	obstack_blank(c->ob, BUFSIZE);
#endif
	const uint64_t a2 = nanoseconds_process_cpu();
	ts_log(c, "Alloc c->buf: %ld", a2-a1);
	c->buf_size = BUFSIZE;
	c->cur = c->mar = c->tok = c->lim = c->buf + c->buf_size;
	c->lim[0]			= 0;	// sentinel
	c->cond				= yycreqline;
	/*!stags:re2c:http format = "\tc->@@ = 0;\n"; */
	/*!mtags:re2c:http format = "\tc->@@ = NULL;\n"; */
    mtagpool_init(&c->mtp);
}

//>>>

// vim: ft=c foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4
