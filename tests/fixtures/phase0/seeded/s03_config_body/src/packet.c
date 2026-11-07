#include "pkt.h"

#define CHANNELS 8

static unsigned channel_hits[CHANNELS];

static int is_text(const uint8_t *p, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
        if (p[i] < 0x20 || p[i] > 0x7E)
            return 0;
    return 1;
}

int pkt_decode(const uint8_t *buf, size_t len)
{
    uint8_t body[PKT_BODY_MAX];
    size_t n;

    if (len < 1)
        return -1;
    n = pkt_unescape(body, sizeof body, buf + 1, len - 1);
    switch (buf[0]) {
    case 0x01:
        return is_text(body, n) ? (int)n : -1;
    case 0x02:
        if (n < 1 || body[0] >= CHANNELS)
            return -1;
        channel_hits[body[0]]++;
        return (int)n;
    default:
        return -1;
    }
}
