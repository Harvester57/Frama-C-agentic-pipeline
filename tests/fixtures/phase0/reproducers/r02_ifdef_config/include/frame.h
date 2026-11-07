#ifndef FRAME_H
#define FRAME_H

#include <stddef.h>
#include <stdint.h>

/* Wire format version; the Makefile overrides this with -DPROTO_VERSION=2. */
#ifndef PROTO_VERSION
#define PROTO_VERSION 1
#endif

#define FRAME_MAGIC     0xA5u
#define FRAME_OVERHEAD  8u      /* magic, type, len(be16), crc32(be32) */
#define FRAME_TYPE_EXT  0x80u   /* v2+: first payload byte holds flags */

/* Frame layout: [A5][type][len hi][len lo][payload ... len][crc32 be]
 * The crc covers the header and the payload. */
struct frame {
    uint8_t type;
    uint16_t len;
    const uint8_t *payload;
    uint8_t ext_flags;
};

int frame_decode(const uint8_t *buf, size_t n, struct frame *f);
uint32_t frame_checksum(const uint8_t *p, size_t n);

#ifdef WITH_COMPRESSION
int frame_decompress(const struct frame *f, uint8_t *out, size_t cap, size_t *out_len);
#endif

#endif
