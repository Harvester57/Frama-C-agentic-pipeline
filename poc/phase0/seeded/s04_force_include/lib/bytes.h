#ifndef BYTES_H
#define BYTES_H

#include <stddef.h>
#include <stdint.h>

/* Reads a big-endian u16 at `off`. The caller guarantees off + 2 <= len. */
uint16_t be16_at(size_t off, const uint8_t *buf, size_t len);

/* Returns 1 when all `n` bytes of `p` are printable ASCII. */
int all_printable(const uint8_t *p, size_t n);

#endif
