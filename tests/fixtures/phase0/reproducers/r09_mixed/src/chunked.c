#include "internal.h"

#ifdef HTTPP_ENABLE_CHUNKED

static int hexval(int c)
{
    if (cls_digit(c))
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    return c - 'A' + 10;
}

/* Decodes "<hex size>\r\n<data>\r\n" ... "0\r\n". Uses p->line_len to
 * count size digits. Trailers and chunk extensions are not supported. */
long chunk_feed(struct httpp *p, const char *data, size_t n)
{
    size_t i = 0, k;
    unsigned char c;

    while (i < n) {
        c = (unsigned char)data[i];
        switch (p->state) {
        case HP_CHUNK_SIZE:
            i++;
            if (cls_hexdig(c)) {
                if (p->body_left > 0x0FFFFFFFUL)
                    return -1;
                p->body_left = p->body_left * 16 + (unsigned long)hexval(c);
                p->line_len++;
            } else if (c == '\n') {
                if (p->line_len == 0)
                    return -1;
                p->line_len = 0;
                if (p->body_left == 0) {
                    p->state = HP_DONE;
                    return (long)i;
                }
                p->state = HP_CHUNK_DATA;
            } else if (c != '\r') {
                return -1;
            }
            break;
        case HP_CHUNK_DATA:
            k = n - i;
            if (k > p->body_left)
                k = (size_t)p->body_left;
            if (CB_CALL(p, on_body, data + i, k))
                return -1;
            i += k;
            p->body_left -= k;
            if (p->body_left == 0)
                p->state = HP_CHUNK_CRLF;
            break;
        case HP_CHUNK_CRLF:
            i++;
            if (c == '\n')
                p->state = HP_CHUNK_SIZE;
            else if (c != '\r')
                return -1;
            break;
        default:
            return -1;
        }
    }
    return (long)i;
}

#ifdef HTTPP_WITH_TRAILERS
static int chunk_trailer_add(struct httpp *p, const char *line, size_t n)
{
    size_t i = 0;
    while (i < n && cls_tchar((unsigned char)line[i]))
        i++;
    if (i == 0 || i >= n || line[i] != ':')
        return -1;
    return hdr_store_add(p, line, i, line + i + 1, n - i - 1);
}
#endif

#endif /* HTTPP_ENABLE_CHUNKED */
