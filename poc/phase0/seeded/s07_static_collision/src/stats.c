#include <string.h>

#include "frame.h"

/* Byte at index `i` of a payload of `n` bytes, or 0 past the end. */
static uint8_t at(const uint8_t *p, size_t n, size_t i)
{
    return i < n ? p[i] : 0;
}

size_t frame_stats(unsigned stride, const uint8_t *buf, size_t len)
{
    size_t counts[256];
    size_t i, best = 0;

    if (stride == 0 || stride > 16)
        return 0;
    memset(counts, 0, sizeof counts);
    for (i = 0; i < len + stride; i += stride)
        counts[at(buf, len, i)]++;
    for (i = 0; i < 256; i++)
        if (counts[i] > best)
            best = counts[i];
    return best;
}

long frame_payload_sum(const uint8_t *buf, size_t len)
{
    size_t hlen, i;
    long sum = 0;

    if (len < 2 || buf[1] < 2 || buf[1] > len)
        return -1;
    hlen = buf[1];
    for (i = hlen; i < len; i++)
        sum += at(buf, len, i);
    return sum;
}
