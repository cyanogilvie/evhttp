#ifndef _FMTSHIM_H
#define _FMTSHIM_H

#include <obstack.h>

#define FAKE_TEMPLATE_APPEND_INT_DECL(func, type) \
	size_t func(struct obstack* ob, type val);

#ifdef __cplusplus
extern "C" {
#endif
	FAKE_TEMPLATE_APPEND_INT_DECL(fmt_obstack_append_int,		int);
	FAKE_TEMPLATE_APPEND_INT_DECL(fmt_obstack_append_size_t,	size_t);
#ifdef __cplusplus
}
#endif

#endif
