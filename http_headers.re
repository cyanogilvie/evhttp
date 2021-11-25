#include "evhttpInt.h"

/*!types:re2c */
/*!include:re2c "common.reh" */

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-label"	// --storable-state causes labels to be generated for yyfill states but this block doesn't use them
#define OB_APPEND_STATIC(ob, str) obstack_grow((ob), (str), sizeof(str));
#define OB_ROLLBACK(ob, to) \
	do { \
		const int size = obstack_size(ob); \
		if (size > to) obstack_free(ob, obstack_base(ob) + to); \
	} while(0)

int ob_write_header_name(struct obstack* ob, const unsigned char* name) //<<<
{
	const unsigned char		*l1, *l2;
	unsigned char			yych;
	const unsigned char*	s = name;

	if (name == NULL) {
		fprintf(stderr, "ob_write_header_name name is NULL\n");
		return 1;
	}

	/*!local:re2c:validate_header_name
		!use:basic;
		!use:http_common;

		@l1 field_name @l2 end {
			obstack_grow(ob, l1, (int)(l2-l1));
			obstack_grow(ob, ": ", 2);
			return 0;
		}

		* {
			fprintf(stderr, "Refusing to write invalid header name: \"%s\"\n", tok);
			return 2;
		}
	*/
}

//>>>
int ob_write_header_value(struct obstack* ob, const unsigned char* value) //<<<
{
	const unsigned char		*l1, *l2;
	unsigned char			yych;
	const unsigned char*	s = value;

	if (name == NULL) {
		fprintf(stderr, "ob_write_header_value value is NULL\n");
		return 1;
	}

	/*!local:re2c:validate_header_value
		!use:basic;
		!use:http_common;

		@l1 field_value @l2 end {
			obstack_grow(ob, l1, (int)(l2-l1));
			obstack_grow(ob, "\r\n", 2);
			return 0;
		}

		* {
			fprintf(stderr, "Refusing to write invalid header value: \"%s\"\n", tok);
			return 2;
		}
	*/
}

//>>>
int ob_write_token(struct obstack* ob, const unsigned char* value) //<<<
{
	const unsigned char		*l1, *l2;
	unsigned char			yych;
	const unsigned char*	s = value;

	if (name == NULL) {
		fprintf(stderr, "ob_write_header_value value is NULL\n");
		return 1;
	}

	/*!local:re2c:validate_token
		!use:basic;
		!use:http_common;

		@l1 token @l2 end {
			obstack_grow(ob, l1, (int)(l2-l1));
			obstack_grow(ob, "\r\n", 2);
			return 0;
		}

		* {
			fprintf(stderr, "Refusing to write invalid header value: \"%s\"\n", tok);
			return 2;
		}
	*/
}

//>>>

void hdr_serialize_content_type(struct obstack* ob, const unsigned char* name/*unused*/, struct header* h) //<<<
{
	const int					rollback_size = obstack_size(ob);
	struct media_type*			content_type = h->field_value.ptr;
	const unsigned char*		s = name ? name : h->field_name_str;
	const unsigned char*		tok = s;
	const int					rollback_size = obstack_size(ob);
	struct media_type_param*	param = content_type->params;

	OB_APPEND_STATIC(ob, "Content-Type: ");

	s = content_type->media_type;
	/*!local:re2c:media_type
		!use:basic;
		!use:http_common;

		@l1 token '/' token @l2 end {
			obstack_grow(ob, l1, (int)(l2-l1));
			goto write_param;
		}

		* {
			fprintf(stderr, "Refusing to write invalid media_type: \"%s\"\n", tok);
			goto error;
		}
	*/

	while (param) {
		obstack_1grow(ob, ';');
		if (ob_write_token(ob, param->name)) goto error;
		obstack_1grow(ob, '=');

		s = param->value;
		/*!local:re2c:validate_media_type_param_value
			!use:basic;
			!use:http_common;

			@l1 token / quoted_string @l2 end {
				obstack_grow(ob, l1, (int)(l2-l1));
				param = param->next;
				continue;
			}

			* {
				fprintf(stderr, "Refusing to write invalid media_type param value: \"%s\"\n", tok);
				goto error;
			}
		*/
	}

	return;

error:
	OB_ROLLBACK(ob, rollback_size);
}

//>>>
void hdr_serialize_transfer_encoding(struct obstack* ob, const unsigned char* name/*unused*/, struct header* h) //<<<
{
	const int					rollback_size = obstack_size(ob);
	struct dl_token*			encoding_token = h->transfer_encoding;

	if (encoding_token == NULL) return;

	OB_APPEND_STATIC(ob, "Transfer-Encoding: ");

	while (encoding_token) {
		if (ob_write_token(ob, encoding_token->token)) goto error;
		encoding_token = encoding_token.dl->next;
		if (encoding_token) OB_APPEND_STATIC(ob, ", ");
	}
	return;

error:
	OB_ROLLBACK(ob, rollback_size);
}

//>>>
void hdr_serialize_connection(struct obstack* ob, const unsigned char* name/*unused*/, struct header* h) //<<<
{
	const int			rollback_size = obstack_size(ob);
	struct dl_token*	token = h->connection;

	if (encoding_token == NULL) return;

	OB_APPEND_STATIC(ob, "Connection: ");

	while (encoding_token) {
		if (ob_write_token(ob, encoding_token->token)) goto error;
		encoding_token = encoding_token.dl->next;
		if (encoding_token) OB_APPEND_STATIC(ob, ", ");
	}

error:
	OB_ROLLBACK(ob, rollback_size);
}

//>>>
#pragma GCC diagnostic pop
void hdr_serialize_str(struct obstack* ob, const unsigned char* name, struct header* h) //<<<
{
	const int				rollback_size = obstack_size(ob);

	if (ob_write_header_name (ob, name ? name : h->field_name_str))	goto error;
	if (ob_write_header_value(ob, h->field_value.str))				goto error;
	return;

error:
	OB_ROLLBACK(ob, rollback_size);
}

//>>>
void hdr_serialize_int(struct obstack* ob, const unsigned char* name, struct header* h) //<<<
{
	const int				rollback_size = obstack_size(ob);

	if (ob_write_header_name(ob, name ? name : h->field_name_str)) goto error;

#if 0
	char			intbuf[3*sizeof(int)+2];
	const size_t	numlen = sprintf(intbuf, "%d", h->field_value.integer);

	obstack_grow(ob, intbuf, numlen);
	obstack_grow(ob, "\r\n", 2);
#else
	const unsigned char* base = obstack_base(ob);
	const size_t len = fmt_obstack_append_int(ob, h->field_value.integer);
	fprintf(stderr, "Appended %d bytes to obstack: %.*s\n", len, len, base);
#endif
	return;

error:
	OB_ROLLBACK(ob, rollback_size);
}

//>>>
#undef OB_APPEND_STATIC
#undef OB_ROLLBACK

typedef void serialize_header(struct obstack* ob, const unsigned char* name, struct header* header) header_serialize_cmd;
struct serializer {
	header_serialize_cmd	cb;
	const unsigned char*	name_str;
};

static struct serializer	serializers[HDR_OTHER+1] = {
	[HDR_HOST]				= {&hdr_serialize_str,					"Host"},
	[CONTENT_LENGTH]		= {&hdr_serialize_int,					"Content-Length"},
	[HDR_CONTENT_TYPE]		= {&hdr_serialize_content_type,			NULL},
	[HDR_TRANSFER_ENCODING] = {&hdr_serialize_transfer_encoding,	NULL},
	/*
	[HDR_TE]				= {&hdr_serialize_te,					NULL},
	[HDR_SET_COOKIE]		= {&hdr_serialize_set_cookie,			NULL},
	[HDR_COOKIE]			= {&hdr_serialize_cookie,				NULL},
	*/
	[HDR_CONNECTION]		= {&hdr_serialize_connection,			NULL},
	/*
	[HDR_UPGRADE]			= {&hdr_serialize_upgrade,				NULL},
	*/
	[HDR_USER_AGENT]		= {&hdr_serialize_str,					"User-Agent"},
	[HDR_OTHER]				= {&hdr_serialize_str,					NULL}
};

int serialize_headers(struct obstack* ob, struct headers* headers) //<<<
{
	struct header*	h = dlist_head(headers);

	while (h) {
		const struct serializer*	serializer = serializers[h->field_name];
		if (serializer->cb == NULL) {
			fprintf(stderr, "No serializer for header type %s yet, skipping\n", header_type_name(h->field_name));
			goto skip;
		}
		(serializer->cb)(ob, serializer->name_str, h);
		OB_APPEND_STATIC(ob, "\r\n");

skip:
		h = h->dl.next;
	}
	OB_APPEND_STATIC(ob, "\r\n");

	return 0;
}

//>>>

// vim: ft=c foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4
