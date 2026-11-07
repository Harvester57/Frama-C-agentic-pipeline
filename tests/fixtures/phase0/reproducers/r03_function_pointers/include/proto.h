#ifndef PROTO_H
#define PROTO_H

#include <stddef.h>
#include <stdint.h>

/* Wire message: [op][len][data ... len] */
struct msg {
    uint8_t op;
    uint8_t len;
    const uint8_t *data;
};

/* Output sink chosen by the caller at runtime. */
struct sink {
    int (*write)(void *ctx, const char *s, size_t n);
    void *ctx;
};

/* Returns bytes consumed, or -1 if the buffer holds no complete message. */
int proto_parse(const uint8_t *buf, size_t n, struct msg *m);

/* Runs the handler registered for m->op; -1 if the op is unknown. */
int proto_dispatch(const struct msg *m, struct sink *out);

/* Writes the names of all supported ops, sorted. */
int proto_list_ops(struct sink *out);

#endif
