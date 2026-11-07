#include "pkt.h"

#if defined(FAST_UNESCAPE)

/* Single pass: copies plain bytes and folds each escape pair. */
size_t pkt_unescape(uint8_t *out, size_t cap, const uint8_t *in, size_t len)
{
    size_t i = 0, o = 0;

    while (i < len && o < cap) {
        uint8_t b = in[i++];
        if (b == PKT_ESC)
            b = (uint8_t)(in[i++] ^ 0x20);
        out[o++] = b;
    }
    return o;
}

#elif defined(LEGACY_UNESCAPE)

/* Firmware < 2.0: callers sized `out` for the worst case. */
size_t pkt_unescape(uint8_t *out, size_t cap, const uint8_t *in, size_t len)
{
    size_t i, o = 0;
    int esc = 0;

    (void)cap;
    for (i = 0; i < len; i++) {
        if (!esc && in[i] == PKT_ESC) {
            esc = 1;
            continue;
        }
        out[o++] = esc ? (uint8_t)(in[i] ^ 0x20) : in[i];
        esc = 0;
    }
    return o;
}

#else

/* Portable reference version: a trailing escape byte is dropped. */
size_t pkt_unescape(uint8_t *out, size_t cap, const uint8_t *in, size_t len)
{
    size_t i, o = 0;

    for (i = 0; i < len && o < cap; i++) {
        if (in[i] == PKT_ESC) {
            if (i + 1 >= len)
                break;
            i++;
            out[o++] = (uint8_t)(in[i] ^ 0x20);
        } else {
            out[o++] = in[i];
        }
    }
    return o;
}

#endif

size_t pkt_escape_cost(const uint8_t *buf, size_t len)
{
    size_t i, n = 0;

    for (i = 0; i < len; i++)
        if (buf[i] == PKT_ESC || buf[i] < 0x20)
            n++;
    return n;
}
