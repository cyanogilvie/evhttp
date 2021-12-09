#include "evhttpInt.h"

/*!include:re2c "common.re" */

/*!header:re2c:on */
struct header {
	struct dlist_elem		dl;
	struct header*			type_next;		// Next header of the same name
	enum evhttp_hdr			field_name;
	unsigned char*			field_name_str;			// Both of these are only valid
	int						field_name_str_len;		// if field_name == EVHTTP_HDR_OTHER
	union {
		unsigned char*		str;
		int64_t				integer;
		void*				ptr;		// If used, must not require explicit free (eg. pointer to obstack managed in c->ob is ok)
	} field_value;
};

#define HEADERS_HASH_BUCKETS	32
struct headers {
	struct dlist		dl;
	struct header*		first[EVHTTP_HDR_OTHER];	// pointer to the first instance of HDR_$foo
	struct header*		last[EVHTTP_HDR_OTHER];	// pointer to the last instance of HDR_$foo
	uint32_t			hash_seed;
	struct dlist		hash_buckets[HEADERS_HASH_BUCKETS];
};

evhttp_err serialize_headers(struct obstack* ob, struct headers* headers);
//void append_header(struct headers* headers, struct header* h);
void remove_header(struct headers* headers, struct header* h);
//struct header* new_header(struct obstack* ob);
struct header* last_header(struct headers* headers, enum evhttp_hdr hdr);
void init_headers(struct headers* headers);

static inline void append_header(struct headers* headers, struct header* h) //<<<
{
	dlist_append(headers, h);
	if (h->field_name == EVHTTP_HDR_OTHER) {
		const uint32_t	hash_bucket = murmurhash3(h->field_name_str, h->field_name_str_len, headers->hash_seed) % HEADERS_HASH_BUCKETS;

		dlist_append(&headers->hash_buckets[hash_bucket], h);
	} else {
		if (headers->last[h->field_name] == NULL) {
			headers->first[h->field_name] = h;
			headers->last[h->field_name] = h;
		} else {
			headers->last[h->field_name]->type_next = h;
			headers->last[h->field_name] = h;
		}
	}
}

//>>>
static inline struct header* new_header(struct obstack* ob) //<<<
{
	return (struct header*)obstack_alloc(ob, sizeof(struct header));
}

//>>>
/*!header:re2c:off */

#define OB_APPEND_STATIC(ob, str) obstack_grow((ob), (str), sizeof(str)-1)
#if 0
#define OB_APPEND_STATIC(ob, str) \
	do { \
		fprintf(stderr, "obstack_grow_static \"%s\": %ld\n", (str), sizeof(str)-1); \
		obstack_grow((ob), (str), sizeof(str)-1); \
	} while(0)
#endif

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-label"	// --storable-state causes labels to be generated for yyfill states but this block doesn't use them
#define OB_ROLLBACK(ob, to) \
	do { \
		const int size = obstack_object_size(ob); \
		if (size > to) obstack_free(ob, obstack_base(ob) + to); \
	} while(0)

evhttp_err ob_write_header_name(struct obstack* ob, unsigned char* name) //<<<
{
	evhttp_err				err = {NULL, EVHTTP_OK};
	unsigned char			*mar, *l1, *l2;
	unsigned char*			s = name;
	/*!stags:re2c:validate_header_name format = "\tunsigned char*\t\t@@;\n"; */

	if (name == NULL) {
		err = ERR("ob_write_header_name name is NULL", EVHTTP_ERR_INVALID);
		goto finally;
	}

	/*!local:re2c:validate_header_name
		!use:basic;
		!use:http_common;

		@l1 field_name @l2 end {
			obstack_grow(ob, l1, (int)(l2-l1));
			obstack_grow(ob, ": ", 2);
			goto finally;
		}

		* {
			err = ERR("Refusing to write invalid header name", EVHTTP_ERR_INVALID);
			goto finally;
		}
	*/

finally:
	return err;
}

//>>>
evhttp_err ob_write_header_value(struct obstack* ob, unsigned char* value) //<<<
{
	evhttp_err			err = {NULL, EVHTTP_OK};
	unsigned char		*mar, *l1, *l2;
	unsigned char*		s = value;
	/*!stags:re2c:validate_header_value format = "\tunsigned char*\t\t@@;\n"; */

	if (value == NULL) {
		err = ERR("ob_write_header_value value is NULL", EVHTTP_ERR_INVALID);
		goto finally;
	}

	/*!local:re2c:validate_header_value
		!use:basic;
		!use:http_common;

		@l1 field_value @l2 end {
			obstack_grow(ob, l1, (int)(l2-l1));
			goto finally;
		}

		* {
			err = ERR("Refusing to write invalid header value", EVHTTP_ERR_INVALID);
			goto finally;
		}
	*/

finally:
	return err;
}

//>>>
evhttp_err ob_write_token(struct obstack* ob, unsigned char* value) //<<<
{
	evhttp_err			err = {NULL, EVHTTP_OK};
	unsigned char		*mar, *l1, *l2;
	unsigned char*		s = value;
	/*!stags:re2c:validate_token format = "\tunsigned char*\t\t@@;\n"; */

	if (value == NULL) {
		err = ERR("ob_write_header_value value is NULL", EVHTTP_ERR_INVALID);
		goto finally;
	}

	/*!local:re2c:validate_token
		!use:basic;
		!use:http_common;

		@l1 token @l2 end {
			obstack_grow(ob, l1, (int)(l2-l1));
			goto finally;
		}

		* {
			err = ERR("Refusing to write invalid header value", EVHTTP_ERR_INVALID);
			goto finally;
		}
	*/

finally:
	return err;
}

//>>>

evhttp_err hdr_serialize_content_type(struct obstack* ob, unsigned char* name/*unused*/, struct header* h) //<<<
{
	evhttp_err					err = {NULL, EVHTTP_OK};
	const int					rollback_size = obstack_object_size(ob);
	struct media_type*			content_type = h->field_value.ptr;
	unsigned char*				s = name ? name : h->field_name_str;
	unsigned char				*mar, *l1, *l2;
	struct media_type_param*	param = content_type->params;
	/*!stags:re2c format = "\tunsigned char*\t\t@@;\n"; */

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
			err = ERR("Refusing to write invalid media_type", EVHTTP_ERR_INVALID);
			goto finally;
		}
	*/

write_param:
	while (param) {
		obstack_1grow(ob, ';');
		EVHTTP_CHECK(finally, err, ob_write_token(ob, param->name));
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
				err = ERR("Refusing to write invalid media_type param value", EVHTTP_ERR_INVALID);
				goto finally;
			}
		*/
	}

finally:
	if (err.msg)
		OB_ROLLBACK(ob, rollback_size);

	return err;
}

//>>>
evhttp_err hdr_serialize_transfer_encoding(struct obstack* ob, unsigned char* name/*unused*/, struct header* h) //<<<
{
	evhttp_err					err = {NULL, EVHTTP_OK};
	const int					rollback_size = obstack_object_size(ob);
	struct dl_token*			encoding_token = h->field_value.ptr;

	if (encoding_token == NULL) goto finally;

	OB_APPEND_STATIC(ob, "Transfer-Encoding: ");

	while (encoding_token) {
		EVHTTP_CHECK(finally, err, ob_write_token(ob, encoding_token->token));
		encoding_token = encoding_token->dl.next;
		if (encoding_token) OB_APPEND_STATIC(ob, ", ");
	}

finally:
	if (err.msg)
		OB_ROLLBACK(ob, rollback_size);

	return err;
}

//>>>
evhttp_err hdr_serialize_connection(struct obstack* ob, unsigned char* name/*unused*/, struct header* h) //<<<
{
	evhttp_err			err = {NULL, EVHTTP_OK};
	const int			rollback_size = obstack_object_size(ob);
	struct dl_token*	token = h->field_value.ptr;

	if (token == NULL) goto finally;

	OB_APPEND_STATIC(ob, "Connection: ");

	while (token) {
		EVHTTP_CHECK(finally, err, ob_write_token(ob, token->token));
		token = token->dl.next;
		if (token) OB_APPEND_STATIC(ob, ", ");
	}

finally:
	if (err.msg)
		OB_ROLLBACK(ob, rollback_size);

	return err;
}

//>>>
#pragma GCC diagnostic pop
evhttp_err hdr_serialize_str(struct obstack* ob, unsigned char*const name, struct header* h) //<<<
{
	evhttp_err		err = {NULL, EVHTTP_OK};
	const int		rollback_size = obstack_object_size(ob);

	EVHTTP_CHECK(finally, err, ob_write_header_name (ob, name ? name : h->field_name_str));
	EVHTTP_CHECK(finally, err, ob_write_header_value(ob, h->field_value.str));

finally:
	if (err.msg)
		OB_ROLLBACK(ob, rollback_size);

	return err;
}

//>>>
evhttp_err hdr_serialize_int(struct obstack* ob, unsigned char*const name, struct header* h) //<<<
{
	evhttp_err		err = {NULL, EVHTTP_OK};
	const int		rollback_size = obstack_object_size(ob);

	EVHTTP_CHECK(finally, err, ob_write_header_name(ob, name ? name : h->field_name_str));

#if 1
	char			intbuf[3*sizeof(int)+2];
	const size_t	numlen = sprintf(intbuf, "%ld", h->field_value.integer);

	obstack_grow(ob, intbuf, numlen);
#else
	unsigned char* base = obstack_base(ob);
	const int len = fmt_obstack_append_int(ob, h->field_value.integer);
	fprintf(stderr, "Appended %d bytes to obstack: %.*s\n", len, len, base);
#endif

finally:
	if (err.msg)
		OB_ROLLBACK(ob, rollback_size);

	return err;
}

//>>>
#undef OB_ROLLBACK

typedef evhttp_err (serialize_header_cmd)(struct obstack* ob, unsigned char*const name, struct header* header);
struct serializer {
	serialize_header_cmd*	cb;
	char*					name_str;
};

static struct serializer	serializers[EVHTTP_HDR_OTHER+1] = {
	[EVHTTP_HDR_HOST]				= {&hdr_serialize_str,					"Host"},
	[EVHTTP_HDR_CONTENT_LENGTH]		= {&hdr_serialize_int,					"Content-Length"},
	[EVHTTP_HDR_CONTENT_TYPE]		= {&hdr_serialize_content_type,			NULL},
	[EVHTTP_HDR_TRANSFER_ENCODING]	= {&hdr_serialize_transfer_encoding,	NULL},
	/*
	[EVHTTP_HDR_TE]					= {&hdr_serialize_te,					NULL},
	[EVHTTP_HDR_SET_COOKIE]			= {&hdr_serialize_set_cookie,			NULL},
	[EVHTTP_HDR_COOKIE]				= {&hdr_serialize_cookie,				NULL},
	*/
	[EVHTTP_HDR_CONNECTION]			= {&hdr_serialize_connection,			NULL},
	/*
	[EVHTTP_HDR_UPGRADE]			= {&hdr_serialize_upgrade,				NULL},
	*/
	[EVHTTP_HDR_USER_AGENT]			= {&hdr_serialize_str,					"User-Agent"},
	[EVHTTP_HDR_OTHER]				= {&hdr_serialize_str,					NULL}
};

const char* header_type_name(enum evhttp_hdr header) //<<<
{
#define hdr_lookup(v) case v:	return #v;
	switch (header) {
		hdr_lookup(EVHTTP_HDR_HOST)
		hdr_lookup(EVHTTP_HDR_CONTENT_LENGTH)
		hdr_lookup(EVHTTP_HDR_CONTENT_TYPE)
		hdr_lookup(EVHTTP_HDR_TRANSFER_ENCODING)
		hdr_lookup(EVHTTP_HDR_TE)
		hdr_lookup(EVHTTP_HDR_SET_COOKIE)
		hdr_lookup(EVHTTP_HDR_COOKIE)
		hdr_lookup(EVHTTP_HDR_CONNECTION)
		hdr_lookup(EVHTTP_HDR_UPGRADE)
		hdr_lookup(EVHTTP_HDR_USER_AGENT)
		hdr_lookup(EVHTTP_HDR_OTHER)
		default:
			return "<invalid hdr value>";
	}
#undef hdr_lookup
}

//>>>

void remove_header(struct headers* headers, struct header* h) //<<<
{
	const enum evhttp_hdr	field_name = h->field_name;

	dlist_remove(headers, h);

	if (field_name != EVHTTP_HDR_OTHER) {
		struct header* scan = headers->first[field_name];

		if (scan == h) {
			headers->first[field_name] = h->type_next;
		} else {
			while (scan->type_next) {
				if (scan->type_next == h) {
					scan->type_next = h->type_next;
					break;
				}
				scan = scan->type_next;
			}
		}
	}
}

//>>>
evhttp_err serialize_headers(struct obstack* ob, struct headers* headers) //<<<
{
	evhttp_err		err = {NULL, EVHTTP_OK};
	struct header*	h = dlist_head(headers);

	while (h) {
		const struct serializer*	serializer = &serializers[h->field_name];
		if (serializer->cb == NULL) {
			fprintf(stderr, "No serializer for header type %s yet, skipping\n", header_type_name(h->field_name));
			goto skip;
		}
		err = (serializer->cb)(ob, (unsigned char*const)serializer->name_str, h);
		if (err.msg) goto finally;
		OB_APPEND_STATIC(ob, "\r\n");

skip:
		h = h->dl.next;
	}
	OB_APPEND_STATIC(ob, "\r\n");

finally:
	return err;
}

//>>>
struct header* last_header(struct headers* headers, enum evhttp_hdr hdr) // return the last instance of hdr, or NULL if none
{
	struct header*	header;

	if (hdr == EVHTTP_HDR_OTHER)
		return NULL; // Not supported (yet?)

	header = headers->first[hdr];
	if (header == NULL)
		return NULL;

	while (header->type_next)
		header = header->type_next;

	return header;
}

//>>>
void init_headers(struct headers* headers) //<<<
{
	memset(headers, 0, sizeof *headers);
	headers->hash_seed = murmurhash3(&headers, sizeof headers, 0);	// Hash the address of the headers struct as the hash seed
}

//>>>

#undef OB_APPEND_STATIC

// vim: ft=c foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4
