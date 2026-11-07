#include "compat.h"

static int b64_value(uint8_t c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;
    return -1;
}

long b64_decode(uint8_t *out, size_t cap, const uint8_t *in, size_t len)
{
    uint32_t acc = 0;
    size_t i, o = 0;
    int q = 0;

    for (i = 0; i < len && in[i] != '='; i++) {
        int v = b64_value(in[i]);
        if (v < 0)
            continue;
        acc = (acc << 6) | (uint32_t)v;
        if (++q == 4) {
            if (o >= cap)
                return -1;
            out[o++] = (uint8_t)(acc >> 16);
            out[o++] = (uint8_t)(acc >> 8);
            out[o++] = (uint8_t)acc;
            acc = 0;
            q = 0;
        }
    }
    /* Trailing partial quantum: 2 chars give 1 byte, 3 chars give 2. */
    if (q >= 2) {
        if (cap - o < (size_t)(q - 1))
            return -1;
        acc <<= 6 * (4 - q);
        out[o++] = (uint8_t)(acc >> 16);
        if (q == 3)
            out[o++] = (uint8_t)(acc >> 8);
    }
    return (long)o;
}

uint32_t load_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
