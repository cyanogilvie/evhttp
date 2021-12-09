#ifndef _EVHTTP_H
#define _EVHTTP_H

#define EVHTTP_CHECK(label, var, call)		do { var = call; if (var.msg) goto label; } while(0)

#ifdef __cplusplus
extern "C" {
#endif

struct evhttp_con;
struct evhttp;

struct evhttp_buf;

typedef void (evhttp_msg_handler)(struct evhttp_con* w);
typedef void (evhttp_releaser)(void* data);
typedef int (evhttp_streamer)(void* data, struct evhttp_buf* chunk);

enum evhttp_err_code {
	EVHTTP_ERR_NONE=0,
	EVHTTP_OK,
	EVHTTP_ERR_SOCK,			// Could not create socket
	EVHTTP_ERR_SOCKOPT,
	EVHTTP_ERR_BIND,
	EVHTTP_ERR_LISTEN,
	EVHTTP_ERR_INVALID,			// A supplied parameter is outside of the valid range
	EVHTTP_ERR_UNIMPLEMENTED,	// A requested action is not supported yet
	EVHTTP_ERR_SEQUENCE,		// This action could not be completed in this sequence (ie. handle request by a listener that is shutting down)

	EVHTTP_ERR_END
};

typedef struct {
	const char*				msg;
	enum evhttp_err_code	code;
} evhttp_err;

struct evhttp_buf {
	const char*			bytes;
	ssize_t				len;
	evhttp_releaser*	free;
};
struct evhttp_stream {
	evhttp_streamer*	next_chunk;
	int					ready_fd;
};

enum evhttp_source {
	EVHTTP_SOURCE_UNDEF=0,
	EVHTTP_SOURCE_BUF,
	EVHTTP_SOURCE_STREAM
};

enum evhttp_method {
	EVHTTP_METHOD_UNSPECIFIED=0,
	EVHTTP_METHOD_GET,
	EVHTTP_METHOD_HEAD,
	EVHTTP_METHOD_POST,
	EVHTTP_METHOD_PUT,
	EVHTTP_METHOD_DELETE,
	EVHTTP_METHOD_CONNECT,
	EVHTTP_METHOD_OPTIONS,
	EVHTTP_METHOD_TRACE,
	EVHTTP_METHOD_CUSTOM			// Custom method specified, string is in con_state.custom_method
};

enum evhttp_hdr {
	EVHTTP_HDR_HOST,
	EVHTTP_HDR_CONTENT_LENGTH,
	EVHTTP_HDR_CONTENT_TYPE,
	EVHTTP_HDR_TRANSFER_ENCODING,
	EVHTTP_HDR_TE,
	EVHTTP_HDR_SET_COOKIE,
	EVHTTP_HDR_COOKIE,
	EVHTTP_HDR_CONNECTION,
	EVHTTP_HDR_UPGRADE,
	EVHTTP_HDR_USER_AGENT,

	EVHTTP_HDR_OTHER					// field_name_str holds the header name, must be last
};

evhttp_err evhttp_server(evhttp_msg_handler* cb, struct evhttp** evh);
void evhttp_handle_events(struct evhttp* evh);
evhttp_err evhttp_server_listen(struct evhttp* evh, const char* node, const char* service);
int evhttp_fd(struct evhttp* evh);
size_t evhttp_con_get_body_len(struct evhttp_con* con);
const unsigned char* evhttp_con_get_body(struct evhttp_con* con);
enum evhttp_method evhttp_con_get_method(struct evhttp_con* con);

//evhttp_err evhttp_con_set_status(struct evhhtp_con* con, int status);
struct evhttp_con_set_status_args {
	struct evhttp_con*	con;
	int					status;
	struct evhttp_buf	reason;
};
evhttp_err evhttp_con_set_status_(struct evhttp_con_set_status_args args);
#define evhttp_con_set_status(c, ...) evhttp_con_set_status_((struct evhttp_con_set_status_args){.reason=NULL,-1, .con=(c), __VA_ARGS__})

//evhttp_err evhttp_con_set_body(struct evhttp_con* con, const char* content_type, const char* body, ssize_t body_len, evhttp_releaser free_body);
struct evhttp_con_set_body_args {
	struct evhttp_con*	con;
	union {
		struct evhttp_buf		buf;
		struct evhttp_stream	stream;
	};
	const char*			content_type;
	enum evhttp_source	source;
};
evhttp_err evhttp_con_set_body_(struct evhttp_con_set_body_args args);
#define evhttp_con_set_body(c, ...) evhttp_con_set_body_((struct evhttp_con_set_body_args){.source=EVHTTP_SOURCE_BUF, .buf.len=-1, .con=(c), __VA_ARGS__})

int evhttp_con_target_match(struct evhttp_con* con, const char* target_pattern);
evhttp_err evhttp_con_respond(struct evhttp_con* con);

struct evhttp_con_set_header_args {
	struct evhttp_con*	con;
	enum evhttp_hdr		name;
	struct evhttp_buf	name_str;
	union {
		struct evhttp_buf	str;
		int64_t				integer;
		void*				ptr;		// If used, must not require explicit free (eg. pointer to obstack managed in c->ob is ok)
	} value;
};
evhttp_err evhttp_con_set_header_(struct evhttp_con_set_header_args args);
#define evhttp_con_set_header(c, ...) evhttp_con_set_header_((struct evhttp_con_set_header_args){.con=(c), __VA_ARGS__})

evhttp_err evhttp_close(struct evhttp** con);

#ifdef __cplusplus
}
#endif
#endif
