#include <string.h>
#include "internal.h"

/* Strips optional whitespace on both ends of [*s, *s+n). Same name as
 * the static helper in parser.c, different signature. */
static size_t trim(const char **s, size_t n)
{
    while (n > 0 && cls_ows((unsigned char)**s)) {
        (*s)++;
        n--;
    }
    while (n > 0 && cls_ows((unsigned char)(*s)[n - 1]))
        n--;
    return n;
}

int hdr_store_add(struct httpp *p, const char *name, size_t nlen,
                  const char *value, size_t vlen)
{
    struct httpp_header *h;

    if (p->nheaders >= HTTPP_MAX_HEADERS)
        return -1;
    vlen = trim(&value, vlen);
    if (nlen >= sizeof p->headers[0].name || vlen >= sizeof p->headers[0].value)
        return -1;
    h = &p->headers[p->nheaders++];
    memcpy(h->name, name, nlen);
    h->name[nlen] = '\0';
    memcpy(h->value, value, vlen);
    h->value[vlen] = '\0';
    return 0;
}

const char *httpp_header_get(const struct httpp *p, const char *name)
{
    size_t i;
    for (i = 0; i < p->nheaders; i++)
        if (httpp_strcasecmp(p->headers[i].name, name) == 0)
            return p->headers[i].value;
    return NULL;
}
