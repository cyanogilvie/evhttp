#include "fmtshim.h"
#include <fmt/format.h>

extern "C" {

#define FAKE_TEMPLATE_APPEND_INT(type) \
	size_t fmt_obstack_append_##type(struct obstack* ob, type val) \
	{ \
		auto fi = fmt::format_int(val); \
		obstack_grow(ob, fi.data(), fi.size()); \
		return fi.size(); \
	}

FAKE_TEMPLATE_APPEND_INT(int);
FAKE_TEMPLATE_APPEND_INT(size_t);

}

// vim: foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4
