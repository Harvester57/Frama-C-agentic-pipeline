#include "bytes.h"

uint16_t be16_at(size_t off, const uint8_t *buf, size_t len)
{
    (void)len; /* bounds are the caller's job; kept for debug builds */
    return (uint16_t)((buf[off] << 8) | buf[off + 1]);
}

int all_printable(const uint8_t *p, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
        if (p[i] < 0x20 || p[i] > 0x7E)
            return 0;
    return 1;
}
