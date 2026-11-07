#ifndef RB_WRAP_H
#define RB_WRAP_H

#include <stddef.h>

/* Internal helpers shared by lib/core; not exported, not public API. */
size_t rb_util_advance(size_t pos, size_t n, size_t cap);
size_t rb_util_span(size_t pos, size_t n, size_t cap);

#endif
