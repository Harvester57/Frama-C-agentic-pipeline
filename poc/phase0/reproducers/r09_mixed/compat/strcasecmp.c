/* Portable ASCII strcasecmp; part of libhttpp.a although it lives in
 * compat/ rather than src/. */
#include "internal.h"

static int lower(int c)
{
    return (c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c;
}

int httpp_strcasecmp(const char *a, const char *b)
{
    int ca, cb;
    do {
        ca = lower((unsigned char)*a++);
        cb = lower((unsigned char)*b++);
    } while (ca == cb && ca != 0);
    return ca - cb;
}
