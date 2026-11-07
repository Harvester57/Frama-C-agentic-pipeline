#include <stdlib.h>
#include <string.h>
#include "internal.h"

/* Drops trailing CRs and NUL-terminates the line buffer. */
static size_t trim(char *s, size_t n)
{
    while (n > 0 && s[n - 1] == '\r')
        n--;
    s[n] = '\0';
    return n;
}

static int parse_request_line(struct httpp *p)
{
    char *line = p->line, *sp1, *sp2;
    size_t i = 0;

    while (cls_tchar((unsigned char)line[i]))
        i++;
    if (i == 0 || line[i] != ' ')
        return -1;
    sp1 = line + i;
    *sp1 = '\0';
    sp2 = strchr(sp1 + 1, ' ');
    if (!sp2 || sp2 == sp1 + 1)
        return -1;
    *sp2 = '\0';
    if (strncmp(sp2 + 1, "HTTP/1.", 7) != 0 ||
        !cls_digit((unsigned char)sp2[8]) || sp2[9] != '\0')
        return -1;
    return CB_CALL(p, on_request_line, line, sp1 + 1, sp2[8] - '0');
}

static int parse_header_line(struct httpp *p)
{
    const char *line = p->line;
    size_t n = p->line_len, i = 0;
    const struct httpp_header *h;

    while (i < n && cls_tchar((unsigned char)line[i]))
        i++;
    if (i == 0 || i >= n || line[i] != ':')
        return -1;
    if (hdr_store_add(p, line, i, line + i + 1, n - i - 1))
        return -1;
    h = &p->headers[p->nheaders - 1];
    return CB_CALL(p, on_header, h->name, h->value);
}

static int end_of_headers(struct httpp *p)
{
    const char *te = httpp_header_get(p, "Transfer-Encoding");
    const char *cl = httpp_header_get(p, "Content-Length");
    char *end;

#ifdef HTTPP_ENABLE_CHUNKED
    if (te && httpp_strcasecmp(te, "chunked") == 0) {
        p->chunked = 1;
        p->state = HP_CHUNK_SIZE;
        return 0;
    }
#endif
    if (te)
        return -1;                      /* unsupported transfer coding */
    if (cl) {
        p->body_left = strtoul(cl, &end, 10);
        if (end == cl || *end != '\0')
            return -1;
    }
    p->state = p->body_left ? HP_BODY : HP_DONE;
    return 0;
}

/* Accumulates bytes into p->line until '\n'. */
static long take_line(struct httpp *p, const char *data, size_t n, int *complete)
{
    size_t i = 0;
    char c;

    *complete = 0;
    while (i < n) {
        c = data[i++];
        if (c == '\n') {
            p->line_len = trim(p->line, p->line_len);
            *complete = 1;
            break;
        }
        if (p->line_len + 1 >= sizeof p->line)
            return -1;
        p->line[p->line_len++] = c;
    }
    return (long)i;
}

static void finish(struct httpp *p)
{
    p->state = HP_DONE;
    if (p->cb && p->cb->on_complete)
        p->cb->on_complete(p->ud);
}

void httpp_reset(struct httpp *p)
{
    p->state = HP_REQ_LINE;
    p->line_len = 0;
    p->nheaders = 0;
    p->body_left = 0;
    p->chunked = 0;
}

void httpp_init(struct httpp *p, const struct httpp_callbacks *cb, void *ud)
{
    p->cb = cb;
    p->ud = ud;
    httpp_reset(p);
}

int httpp_done(const struct httpp *p)
{
    return p->state == HP_DONE;
}

long httpp_feed(struct httpp *p, const char *data, size_t n)
{
    size_t off = 0, k;
    long r;
    int complete;

    while (off < n && p->state != HP_DONE && p->state != HP_ERROR) {
        switch (p->state) {
        case HP_REQ_LINE:
        case HP_HEADERS:
            r = take_line(p, data + off, n - off, &complete);
            if (r < 0)
                goto fail;
            off += (size_t)r;
            if (!complete)
                break;
            if (p->state == HP_REQ_LINE) {
                if (parse_request_line(p))
                    goto fail;
                p->state = HP_HEADERS;
            } else if (p->line_len == 0) {
                if (end_of_headers(p))
                    goto fail;
                if (p->state == HP_DONE)
                    finish(p);
            } else if (parse_header_line(p)) {
                goto fail;
            }
            p->line_len = 0;
            break;
        case HP_BODY:
            k = n - off;
            if (k > p->body_left)
                k = (size_t)p->body_left;
            if (CB_CALL(p, on_body, data + off, k))
                goto fail;
            off += k;
            p->body_left -= k;
            if (p->body_left == 0)
                finish(p);
            break;
#ifdef HTTPP_ENABLE_CHUNKED
        case HP_CHUNK_SIZE:
        case HP_CHUNK_DATA:
        case HP_CHUNK_CRLF:
            r = chunk_feed(p, data + off, n - off);
            if (r < 0)
                goto fail;
            off += (size_t)r;
            if (p->state == HP_DONE)
                finish(p);
            break;
#endif
        default:
            goto fail;
        }
    }
    return (long)off;
fail:
    p->state = HP_ERROR;
    return -1;
}
