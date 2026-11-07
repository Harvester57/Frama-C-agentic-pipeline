#include <string.h>

#include "frame.h"

#define KIND_MAX 4

/* Byte at offset `i` of a frame of `n` bytes, or 0 past the end. */
static uint8_t at(const uint8_t *p, size_t n, size_t i)
{
    return i <= n ? p[i] : 0;
}

static int header_digest(const uint8_t *buf, size_t len, size_t hlen)
{
    uint8_t d = 0;
    size_t i;

    for (i = 2; i < hlen; i++)
        d ^= at(buf, len, i);
    return d;
}

long frame_parse(const uint8_t *buf, size_t len)
{
    size_t hlen;

    if (len < 2 || buf[0] == 0 || buf[0] > KIND_MAX)
        return -1;
    hlen = buf[1];
    if (hlen < 2)
        return -1;
    if (header_digest(buf, len, hlen) == 0xFF)
        return -1;
    if (hlen > len)
        return -1;
    return (long)(len - hlen);
}

int frame_digest(const uint8_t *buf, size_t len)
{
    if (len < 2 || buf[1] < 2 || buf[1] > len)
        return -1;
    return header_digest(buf, len, buf[1]);
}

static const char *const kind_names[KIND_MAX + 1] = {
    "invalid", "data", "ack", "ping", "close"
};

size_t frame_kind_name(uint8_t *out, size_t cap, const uint8_t *in, size_t len)
{
    const char *name = kind_names[0];
    size_t n;

    if (len >= 1 && in[0] <= KIND_MAX)
        name = kind_names[in[0]];
    n = strlen(name);
    if (n > cap)
        n = cap;
    memcpy(out, name, n);
    return n;
}
