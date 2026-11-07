#include <string.h>

#include "handlers.h"

int h_ping(struct reply *r, const uint8_t *p, size_t n)
{
    (void)p;
    if (n != 0 || r->cap < 4)
        return -1;
    memcpy(r->buf, "pong", 4);
    r->used = 4;
    return 0;
}

int h_echo(struct reply *r, const uint8_t *p, size_t n)
{
    if (n > r->cap)
        n = r->cap;
    memcpy(r->buf, p, n);
    r->used = n;
    return 0;
}

int h_sum(struct reply *r, const uint8_t *p, size_t n)
{
    uint8_t s = 0;
    size_t i;

    if (r->cap < 1)
        return -1;
    for (i = 0; i < n; i++)
        s = (uint8_t)(s + p[i]);
    r->buf[0] = s;
    r->used = 1;
    return 0;
}

int h_rev(struct reply *r, const uint8_t *p, size_t n)
{
    size_t i;

    if (n > r->cap)
        n = r->cap;
    for (i = 0; i < n; i++)
        r->buf[i] = p[n - i];
    r->used = n;
    return 0;
}

int h_upper(struct reply *r, const uint8_t *p, size_t n)
{
    size_t i;

    if (n > r->cap)
        n = r->cap;
    for (i = 0; i < n; i++)
        r->buf[i] = (p[i] >= 'a' && p[i] <= 'z') ? (uint8_t)(p[i] - 32) : p[i];
    r->used = n;
    return 0;
}
