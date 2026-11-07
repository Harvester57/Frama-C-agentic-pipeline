#ifndef RINGBUF_H
#define RINGBUF_H

#include <stddef.h>

/* The library is built with -fvisibility=hidden; only RB_API symbols are
 * exported from libringbuf.so. */
#if defined(__GNUC__)
#define RB_API __attribute__((visibility("default")))
#else
#define RB_API
#endif

struct ringbuf {
    unsigned char *data;
    size_t cap;
    size_t head;   /* next byte to read */
    size_t tail;   /* next byte to write */
    size_t used;
};

RB_API int rb_init(struct ringbuf *rb, unsigned char *storage, size_t cap);
RB_API size_t rb_used(const struct ringbuf *rb);
RB_API size_t rb_free_space(const struct ringbuf *rb);
RB_API size_t rb_write(struct ringbuf *rb, const unsigned char *src, size_t n);
RB_API size_t rb_read(struct ringbuf *rb, unsigned char *dst, size_t n);

/* Copies the first complete line (without '\n', NUL-terminated) into dst
 * without consuming it. Returns the line length + 1 (bytes to consume),
 * or 0 if no complete line is buffered or it does not fit in dst. */
RB_API size_t rb_peek_line(const struct ringbuf *rb, unsigned char *dst, size_t cap);

#endif
