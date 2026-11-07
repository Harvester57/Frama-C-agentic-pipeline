#ifndef KV_H
#define KV_H

#include <stddef.h>

/* One "key = value" pair; pointers alias the input buffer. */
struct kv_pair {
    const char *key;
    size_t key_len;
    const char *val;
    size_t val_len;
};

/* Parse the next pair starting at *pos. Returns 1 on a pair, 0 at end of
 * input, -1 on a syntax error (*pos is left at the start of the bad line). */
int kv_next(const char *buf, size_t len, size_t *pos, struct kv_pair *out);

/* Render a pair as key="value" with escaping; returns bytes written
 * (excluding the terminating NUL). */
size_t kv_emit(const struct kv_pair *p, char *out, size_t cap);

#endif
