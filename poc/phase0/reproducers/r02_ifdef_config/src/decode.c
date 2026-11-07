#include "frame.h"

static uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t rd32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

#if PROTO_VERSION >= 2
/* v2 extension: strip the flags byte off the payload. */
static int check_ext_flags(struct frame *f)
{
    if (f->len < 1)
        return -3;
    f->ext_flags = f->payload[0];
    if (f->ext_flags & 0xF0u)       /* reserved bits must be zero */
        return -3;
    f->payload++;
    f->len--;
    return 0;
}
#endif

#ifdef WITH_COMPRESSION
/* Payload is a sequence of (count, byte) pairs. */
static size_t rle_expand(const uint8_t *in, size_t n, uint8_t *out, size_t cap)
{
    size_t i, o = 0;
    for (i = 0; i + 1 < n; i += 2) {
        uint8_t k;
        for (k = 0; k < in[i]; k++) {
            if (o >= cap)
                return (size_t)-1;
            out[o++] = in[i + 1];
        }
    }
    return o;
}

int frame_decompress(const struct frame *f, uint8_t *out, size_t cap, size_t *out_len)
{
    size_t r = rle_expand(f->payload, f->len, out, cap);
    if (r == (size_t)-1)
        return -1;
    *out_len = r;
    return 0;
}
#endif

#if 0
static void dump_frame(const struct frame *f)
{
    printf("type=%u len=%u\n", f->type, f->len);
}
#endif

int frame_decode(const uint8_t *buf, size_t n, struct frame *f)
{
    size_t total;

    if (n < FRAME_OVERHEAD || buf[0] != FRAME_MAGIC)
        return -1;
    f->type = buf[1];
    f->len = rd16(buf + 2);
    f->payload = buf + 4;
    f->ext_flags = 0;
    total = (size_t)f->len + FRAME_OVERHEAD;
    if (total > n)
        return -1;
    if (rd32(buf + 4 + f->len) != frame_checksum(buf, 4 + (size_t)f->len))
        return -2;
#if PROTO_VERSION >= 2
    if ((f->type & FRAME_TYPE_EXT) && check_ext_flags(f))
        return -3;
#endif
    return (int)total;
}
