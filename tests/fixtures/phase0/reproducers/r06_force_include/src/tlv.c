#include <string.h>
#include "tlv.h"
#include "tlvdefs.h"
#include <endian_compat.h>

/* TLV_MAX_DEPTH, ENABLE_NESTED and ENABLE_STRICT come from config.h,
 * which the build force-includes. */
#ifndef TLV_MAX_DEPTH
#error "config.h must be force-included (-include config.h)"
#endif

static int read_header(const uint8_t *p, size_t n, struct tlv_hdr *h)
{
    if (n < TLV_HDR_LEN)
        return -1;
    h->tag = p[0];
    h->len = compat_be16(p + 1);
    if ((size_t)h->len > n - TLV_HDR_LEN)
        return -1;
    return 0;
}

#if ENABLE_STRICT
static int tag_known(uint8_t tag)
{
    switch (tag & ~TLV_TAG_CONSTRUCTED) {
    case 0x01: case 0x02: case 0x04: case 0x10:
        return 1;
    default:
        return 0;
    }
}
#endif

#if ENABLE_NESTED
static int walk_nested(const uint8_t *p, size_t n, int depth, struct tlv_stats *st);
#endif

static int walk_level(const uint8_t *p, size_t n, int depth, struct tlv_stats *st)
{
    size_t off = 0;
    struct tlv_hdr h;

    if (depth > TLV_MAX_DEPTH)
        return -1;
    while (off < n) {
        if (read_header(p + off, n - off, &h))
            return -1;
#if ENABLE_STRICT
        if (!tag_known(h.tag))
            return -1;
#endif
        st->count++;
        if (depth > st->max_depth)
            st->max_depth = depth;
#if ENABLE_NESTED
        if (h.tag & TLV_TAG_CONSTRUCTED) {
            if (walk_nested(p + off + TLV_HDR_LEN, h.len, depth + 1, st))
                return -1;
        } else
#endif
        {
            st->bytes += h.len;
        }
        off += TLV_HDR_LEN + h.len;
    }
    return 0;
}

#if ENABLE_NESTED
static int walk_nested(const uint8_t *p, size_t n, int depth, struct tlv_stats *st)
{
    st->constructed++;
    return walk_level(p, n, depth, st);
}
#endif

int tlv_walk(const uint8_t *buf, size_t n, struct tlv_stats *st)
{
    memset(st, 0, sizeof *st);
    return walk_level(buf, n, 0, st);
}
