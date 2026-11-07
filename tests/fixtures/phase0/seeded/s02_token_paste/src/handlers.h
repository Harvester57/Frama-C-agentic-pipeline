#ifndef HANDLERS_H
#define HANDLERS_H

#include <stddef.h>
#include <stdint.h>

#define REPLY_MAX 64

/* Reply buffer owned by the dispatcher: `buf` holds `cap` bytes. */
struct reply {
    uint8_t *buf;
    size_t cap;
    size_t used;
};

enum {
    OP_ping = 0x01,
    OP_echo = 0x02,
    OP_sum = 0x03,
    OP_rev = 0x04,
    OP_upper = 0x05
};

/* Handlers: `p` holds the `n` payload bytes. Return 0, or -1 on error. */
int h_ping(struct reply *r, const uint8_t *p, size_t n);
int h_echo(struct reply *r, const uint8_t *p, size_t n);
int h_sum(struct reply *r, const uint8_t *p, size_t n);
int h_rev(struct reply *r, const uint8_t *p, size_t n);
int h_upper(struct reply *r, const uint8_t *p, size_t n);

#endif
