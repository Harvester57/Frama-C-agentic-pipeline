#include "demo.h"

static int clamp(int v) { return v > 255 ? 255 : v; }

int demo_sum(const unsigned char *buf, size_t len)
{
    int s = 0;
    for (size_t i = 0; i < len; i++)
        s = clamp(s + buf[i]);
    return s;
}
