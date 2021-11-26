#include "fmtshim.h"
#include <fmt/format.h>

extern "C" {

#define FAKE_TEMPLATE_APPEND_INT(func, type) \
	size_t func(struct obstack* ob, type val) \
	{ \
		auto fi = fmt::format_int(val); \
		obstack_grow(ob, fi.data(), fi.size()); \
		return fi.size(); \
	}

FAKE_TEMPLATE_APPEND_INT(fmt_obstack_append_int,	int);
FAKE_TEMPLATE_APPEND_INT(fmt_obstack_append_size_t,	size_t);

}

// vim: foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4
