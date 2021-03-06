#ifndef _FMTSHIM_H
#define _FMTSHIM_H

#include <obstack.h>

#define FAKE_TEMPLATE_APPEND_INT_DECL(type) \
	size_t fmt_obstack_append_##type(struct obstack* ob, type val);

#ifdef __cplusplus
extern "C" {
#endif
	FAKE_TEMPLATE_APPEND_INT_DECL(int);
	FAKE_TEMPLATE_APPEND_INT_DECL(size_t);
#ifdef __cplusplus
}
#endif

#endif
