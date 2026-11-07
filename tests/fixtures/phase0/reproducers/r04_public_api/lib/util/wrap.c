#include "wrap.h"

/* Position after moving n bytes forward in a ring of size cap (n <= cap). */
size_t rb_util_advance(size_t pos, size_t n, size_t cap)
{
    pos += n;
    if (pos >= cap)
        pos -= cap;
    return pos;
}

/* Largest contiguous chunk (<= n) starting at pos before the wrap point. */
size_t rb_util_span(size_t pos, size_t n, size_t cap)
{
    size_t room = cap - pos;
    return n < room ? n : room;
}
