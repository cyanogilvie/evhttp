#include "evhttpInt.h"

/*!include:re2c "common.re" */

/*!header:re2c:on */
enum hdr {
	HDR_HOST,
	HDR_CONTENT_LENGTH,
	HDR_CONTENT_TYPE,
	HDR_TRANSFER_ENCODING,
	HDR_TE,
	HDR_SET_COOKIE,
	HDR_COOKIE,
	HDR_CONNECTION,
	HDR_UPGRADE,
	HDR_USER_AGENT,

	HDR_OTHER					// field_name_str holds the header name, must be last
};

struct header {
	struct dlist_elem	dl;
	struct header*		type_next;		// Next header of the same name
	enum hdr			field_name;
	unsigned char*		field_name_str;			// Both of these are only valid
	int					field_name_str_len;		// if field_name == HDR_OTHER
	union {
		unsigned char*	str;
		int64_t			integer;
		void*			ptr;		// If used, must not require explicit free (eg. pointer to obstack managed in c->ob is ok)
	} field_value;
};

#define HEADERS_HASH_BUCKETS	32
struct headers {
	struct dlist		dl;
	struct header*		first[HDR_OTHER];	// pointer to the first instance of HDR_$foo
	struct header*		last[HDR_OTHER];	// pointer to the last instance of HDR_$foo
	uint32_t			hash_seed;
	struct dlist		hash_buckets[HEADERS_HASH_BUCKETS];
};

int serialize_headers(struct obstack* ob, struct headers* headers);
void append_header(struct headers* headers, struct header* h);
void remove_header(struct headers* headers, struct header* h);
struct header* new_header(struct obstack* ob);
struct header* last_header(struct headers* headers, enum hdr hdr);
void init_headers(struct headers* headers);

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

int ob_write_header_name(struct obstack* ob, unsigned char* name) //<<<
{
	unsigned char			*mar, *l1, *l2;
	unsigned char*			s = name;
	/*!stags:re2c:validate_header_name format = "\tunsigned char*\t\t@@;\n"; */

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
			fprintf(stderr, "Refusing to write invalid header name: \"%s\"\n", name);
			return 2;
		}
	*/
}

//>>>
int ob_write_header_value(struct obstack* ob, unsigned char* value) //<<<
{
	unsigned char		*mar, *l1, *l2;
	unsigned char*		s = value;
	/*!stags:re2c:validate_header_value format = "\tunsigned char*\t\t@@;\n"; */

	if (value == NULL) {
		fprintf(stderr, "ob_write_header_value value is NULL\n");
		return 1;
	}

	/*!local:re2c:validate_header_value
		!use:basic;
		!use:http_common;

		@l1 field_value @l2 end {
			obstack_grow(ob, l1, (int)(l2-l1));
			return 0;
		}

		* {
			fprintf(stderr, "Refusing to write invalid header value: \"%s\"\n", value);
			return 2;
		}
	*/
}

//>>>
int ob_write_token(struct obstack* ob, unsigned char* value) //<<<
{
	unsigned char		*mar, *l1, *l2;
	unsigned char*		s = value;
	/*!stags:re2c:validate_token format = "\tunsigned char*\t\t@@;\n"; */

	if (value == NULL) {
		fprintf(stderr, "ob_write_header_value value is NULL\n");
		return 1;
	}

	/*!local:re2c:validate_token
		!use:basic;
		!use:http_common;

		@l1 token @l2 end {
			obstack_grow(ob, l1, (int)(l2-l1));
			return 0;
		}

		* {
			fprintf(stderr, "Refusing to write invalid header value: \"%s\"\n", value);
			return 2;
		}
	*/
}

//>>>

void hdr_serialize_content_type(struct obstack* ob, unsigned char* name/*unused*/, struct header* h) //<<<
{
	const int					rollback_size = obstack_object_size(ob);
	struct media_type*			content_type = h->field_value.ptr;
	unsigned char*				s = name ? name : h->field_name_str;
	unsigned char				*tok = s, *mar, *l1, *l2;
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
			fprintf(stderr, "Refusing to write invalid media_type: \"%s\"\n", tok);
			goto error;
		}
	*/

write_param:
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
void hdr_serialize_transfer_encoding(struct obstack* ob, unsigned char* name/*unused*/, struct header* h) //<<<
{
	const int					rollback_size = obstack_object_size(ob);
	struct dl_token*			encoding_token = h->field_value.ptr;

	if (encoding_token == NULL) return;

	OB_APPEND_STATIC(ob, "Transfer-Encoding: ");

	while (encoding_token) {
		if (ob_write_token(ob, encoding_token->token)) goto error;
		encoding_token = encoding_token->dl.next;
		if (encoding_token) OB_APPEND_STATIC(ob, ", ");
	}
	return;

error:
	OB_ROLLBACK(ob, rollback_size);
}

//>>>
void hdr_serialize_connection(struct obstack* ob, unsigned char* name/*unused*/, struct header* h) //<<<
{
	const int			rollback_size = obstack_object_size(ob);
	struct dl_token*	token = h->field_value.ptr;

	if (token == NULL) return;

	OB_APPEND_STATIC(ob, "Connection: ");

	while (token) {
		if (ob_write_token(ob, token->token)) goto error;
		token = token->dl.next;
		if (token) OB_APPEND_STATIC(ob, ", ");
	}

error:
	OB_ROLLBACK(ob, rollback_size);
}

//>>>
#pragma GCC diagnostic pop
void hdr_serialize_str(struct obstack* ob, unsigned char*const name, struct header* h) //<<<
{
	const int				rollback_size = obstack_object_size(ob);

	if (ob_write_header_name (ob, name ? name : h->field_name_str))	goto error;
	if (ob_write_header_value(ob, h->field_value.str))				goto error;
	return;

error:
	OB_ROLLBACK(ob, rollback_size);
}

//>>>
void hdr_serialize_int(struct obstack* ob, unsigned char*const name, struct header* h) //<<<
{
	const int				rollback_size = obstack_object_size(ob);

	if (ob_write_header_name(ob, name ? name : h->field_name_str)) goto error;

#if 1
	char			intbuf[3*sizeof(int)+2];
	const size_t	numlen = sprintf(intbuf, "%ld", h->field_value.integer);

	obstack_grow(ob, intbuf, numlen);
#else
	unsigned char* base = obstack_base(ob);
	const int len = fmt_obstack_append_int(ob, h->field_value.integer);
	fprintf(stderr, "Appended %d bytes to obstack: %.*s\n", len, len, base);
#endif
	return;

error:
	OB_ROLLBACK(ob, rollback_size);
}

//>>>
#undef OB_ROLLBACK

typedef void (serialize_header_cmd)(struct obstack* ob, unsigned char*const name, struct header* header);
struct serializer {
	serialize_header_cmd*	cb;
	char*					name_str;
};

static struct serializer	serializers[HDR_OTHER+1] = {
	[HDR_HOST]				= {&hdr_serialize_str,					"Host"},
	[HDR_CONTENT_LENGTH]	= {&hdr_serialize_int,					"Content-Length"},
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

const char* header_type_name(enum hdr header) //<<<
{
#define hdr_lookup(v) case v:	return #v;
	switch (header) {
		hdr_lookup(HDR_HOST)
		hdr_lookup(HDR_CONTENT_LENGTH)
		hdr_lookup(HDR_CONTENT_TYPE)
		hdr_lookup(HDR_TRANSFER_ENCODING)
		hdr_lookup(HDR_TE)
		hdr_lookup(HDR_SET_COOKIE)
		hdr_lookup(HDR_COOKIE)
		hdr_lookup(HDR_CONNECTION)
		hdr_lookup(HDR_UPGRADE)
		hdr_lookup(HDR_USER_AGENT)
		hdr_lookup(HDR_OTHER)
		default:
			return "<invalid hdr value>";
	}
#undef hdr_lookup
}

//>>>

void append_header(struct headers* headers, struct header* h) //<<<
{
	dlist_append(headers, h);
	if (h->field_name == HDR_OTHER) {
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
void remove_header(struct headers* headers, struct header* h) //<<<
{
	const enum hdr	field_name = h->field_name;

	dlist_remove(headers, h);

	if (field_name != HDR_OTHER) {
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
struct header* new_header(struct obstack* ob) //<<<
{
	return (struct header*)obstack_alloc(ob, sizeof(struct header));
}

//>>>
void new_header_other(struct con_state* c, const unsigned char* field_name_str, int field_name_str_len, const unsigned char* field_value, int field_value_len) //<<<
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
void new_header_str(struct con_state* c, enum hdr field_name, const unsigned char* field_value, int field_value_len) //<<<
{
	struct header*	hdr = new_header(c->ob);

	hdr->field_name			= field_name;
	hdr->field_value.str	= obstack_copy0(c->ob, field_value, field_value_len);

	append_header(&c->headers, hdr);
}

//>>>
int push_te(struct con_state* c, enum te_types type) //<<<
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
int push_te_accept(struct con_state* c, const unsigned char* r1, const unsigned char* r2, enum te_types type) //<<<
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
int serialize_headers(struct obstack* ob, struct headers* headers) //<<<
{
	struct header*	h = dlist_head(headers);

	while (h) {
		const struct serializer*	serializer = &serializers[h->field_name];
		if (serializer->cb == NULL) {
			fprintf(stderr, "No serializer for header type %s yet, skipping\n", header_type_name(h->field_name));
			goto skip;
		}
		(serializer->cb)(ob, (unsigned char*const)serializer->name_str, h);
		OB_APPEND_STATIC(ob, "\r\n");

skip:
		h = h->dl.next;
	}
	OB_APPEND_STATIC(ob, "\r\n");

	return 0;
}

//>>>
struct header* last_header(struct headers* headers, enum hdr hdr) // return the last instance of hdr, or NULL if none
{
	struct header*	header;

	if (hdr == HDR_OTHER)
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
