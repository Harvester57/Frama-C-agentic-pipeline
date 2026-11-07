#include <string.h>
#include "ringbuf.h"
#include "../util/wrap.h"

int rb_init(struct ringbuf *rb, unsigned char *storage, size_t cap)
{
    if (!rb || !storage || cap == 0)
        return -1;
    rb->data = storage;
    rb->cap = cap;
    rb->head = 0;
    rb->tail = 0;
    rb->used = 0;
    return 0;
}

size_t rb_used(const struct ringbuf *rb)
{
    return rb->used;
}

/* Public API that is also used internally by rb_write. */
size_t rb_free_space(const struct ringbuf *rb)
{
    return rb->cap - rb_used(rb);
}

size_t rb_write(struct ringbuf *rb, const unsigned char *src, size_t n)
{
    size_t room = rb_free_space(rb), done = 0, chunk;

    if (n > room)
        n = room;
    while (done < n) {
        chunk = rb_util_span(rb->tail, n - done, rb->cap);
        memcpy(rb->data + rb->tail, src + done, chunk);
        rb->tail = rb_util_advance(rb->tail, chunk, rb->cap);
        done += chunk;
    }
    rb->used += n;
    return n;
}

size_t rb_read(struct ringbuf *rb, unsigned char *dst, size_t n)
{
    size_t avail = rb_used(rb), done = 0, chunk;

    if (n > avail)
        n = avail;
    while (done < n) {
        chunk = rb_util_span(rb->head, n - done, rb->cap);
        if (dst)
            memcpy(dst + done, rb->data + rb->head, chunk);
        rb->head = rb_util_advance(rb->head, chunk, rb->cap);
        done += chunk;
    }
    rb->used -= n;
    return n;
}
