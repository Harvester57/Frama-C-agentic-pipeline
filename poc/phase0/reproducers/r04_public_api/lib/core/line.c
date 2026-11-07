#include "ringbuf.h"
#include "../util/wrap.h"

size_t rb_peek_line(const struct ringbuf *rb, unsigned char *dst, size_t cap)
{
    size_t pos = rb->head, i;

    for (i = 0; i < rb->used; i++) {
        unsigned char c = rb->data[pos];
        if (c == '\n') {
            if (cap == 0)
                return 0;
            dst[i] = '\0';
            return i + 1;
        }
        if (i + 1 >= cap)
            return 0;
        dst[i] = c;
        pos = rb_util_advance(pos, 1, rb->cap);
    }
    return 0;
}
