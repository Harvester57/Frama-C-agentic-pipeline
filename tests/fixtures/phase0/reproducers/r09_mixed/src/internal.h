#ifndef HTTPP_INTERNAL_H
#define HTTPP_INTERNAL_H

#include "httpp.h"

/* Character classes, generated in chars.c by DEFINE_CLASS. */
int cls_digit(int c);
int cls_alpha(int c);
int cls_hexdig(int c);
int cls_tchar(int c);
int cls_ows(int c);

/* headers.c */
int hdr_store_add(struct httpp *p, const char *name, size_t nlen,
                  const char *value, size_t vlen);

/* compat/strcasecmp.c */
int httpp_strcasecmp(const char *a, const char *b);

#ifdef HTTPP_ENABLE_CHUNKED
/* chunked.c */
long chunk_feed(struct httpp *p, const char *data, size_t n);
#endif

/* Invoke an optional user callback that takes arguments. */
#define CB_CALL(p, fn, ...) \
    (((p)->cb && (p)->cb->fn) ? (p)->cb->fn((p)->ud, __VA_ARGS__) : 0)

#endif
