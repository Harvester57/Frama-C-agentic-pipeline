#ifndef CURSOR_H
#define CURSOR_H

#include <stddef.h>
#include <stdint.h>

#define LABEL_MAX 16

struct cursor {
    const uint8_t *p;
    size_t len;
    size_t pos;
};

/* Big-endian readers generated in readers.c. Return 0, or -1 when short. */
int read_u8(struct cursor *c, uint8_t *out);
int read_u16(struct cursor *c, uint16_t *out);
int read_u32(struct cursor *c, uint32_t *out);

/*
 * Reads a length-prefixed label into `out`, which holds LABEL_MAX bytes,
 * and NUL-terminates it. Returns the label length, or -1.
 */
int read_label(struct cursor *c, char *out);

#endif
