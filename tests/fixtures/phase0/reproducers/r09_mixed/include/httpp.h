#ifndef HTTPP_H
#define HTTPP_H

#include <stddef.h>

/* Incremental HTTP/1.x request parser (request line, headers, body).
 * Chunked transfer coding is supported when built with
 * -DHTTPP_ENABLE_CHUNKED. */

#define HTTPP_MAX_HEADERS 32
#define HTTPP_MAX_LINE 1024

enum httpp_state {
    HP_REQ_LINE,
    HP_HEADERS,
    HP_BODY,
    HP_CHUNK_SIZE,
    HP_CHUNK_DATA,
    HP_CHUNK_CRLF,
    HP_DONE,
    HP_ERROR
};

struct httpp_header {
    char name[64];
    char value[256];
};

/* User callbacks; any of them may be NULL. A non-zero return aborts. */
struct httpp_callbacks {
    int (*on_request_line)(void *ud, const char *method, const char *target, int minor);
    int (*on_header)(void *ud, const char *name, const char *value);
    int (*on_body)(void *ud, const char *data, size_t n);
    void (*on_complete)(void *ud);
};

struct httpp {
    enum httpp_state state;
    char line[HTTPP_MAX_LINE];
    size_t line_len;
    struct httpp_header headers[HTTPP_MAX_HEADERS];
    size_t nheaders;
    unsigned long body_left;
    int chunked;
    const struct httpp_callbacks *cb;
    void *ud;
};

void httpp_init(struct httpp *p, const struct httpp_callbacks *cb, void *ud);
void httpp_reset(struct httpp *p);
/* Returns bytes consumed (stops after a complete request) or -1. */
long httpp_feed(struct httpp *p, const char *data, size_t n);
int httpp_done(const struct httpp *p);
/* Case-insensitive header lookup; NULL if absent. */
const char *httpp_header_get(const struct httpp *p, const char *name);

#endif
