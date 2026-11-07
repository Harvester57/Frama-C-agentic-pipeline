#ifndef COMPAT_H
#define COMPAT_H

#include <stddef.h>
#include <stdint.h>

/*
 * Decodes base64 text into `out` (`cap` bytes). Characters outside the
 * alphabet are skipped; '=' ends the input. Returns the decoded length,
 * or -1 when `out` is too small.
 */
long b64_decode(uint8_t *out, size_t cap, const uint8_t *in, size_t len);

/* Reads a big-endian u32. The caller guarantees 4 readable bytes at `p`. */
uint32_t load_be32(const uint8_t *p);

#endif
