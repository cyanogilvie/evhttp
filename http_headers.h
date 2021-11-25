#ifndef _HTTP_HEADERS_H
#define _HTTP_HEADERS_H

enum header {
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
	enum header			field_name;
	unsigned char*		field_name_str;
	union {
		unsigned char*	str;
		int64_t			integer;
		void*			ptr;		// If used, must not require explicit free (eg. pointer to obstack managed in c->meta is ok)
	} field_value;
};

struct headers {
	struct dlist		dl;
	struct header*		head;				// head of linked list of headers
	struct header*		tail;
	struct header*		first[HDR_OTHER];	// pointer to the first instance of HDR_$foo
	struct header*		last[HDR_OTHER];	// pointer to the last instance of HDR_$foo
};

int serialize_headers(struct obstack* ob, struct headers* headers);

#endif
