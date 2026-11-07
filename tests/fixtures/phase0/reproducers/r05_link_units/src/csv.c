#include "csv.h"

void csv_init(struct csv_reader *r, const char *buf, size_t len)
{
    r->buf = buf;
    r->len = len;
    r->pos = 0;
}

int csv_next_field(struct csv_reader *r, struct csv_field *f)
{
    size_t i = r->pos, start;

    if (i >= r->len)
        return 0;
    f->quoted = 0;
    f->last_in_row = 0;

    if (r->buf[i] == '"') {
        start = ++i;
        for (;;) {
            if (i >= r->len)
                return -1;                  /* unterminated quote */
            if (r->buf[i] == '"') {
                if (i + 1 < r->len && r->buf[i + 1] == '"') {
                    i += 2;
                    continue;
                }
                break;
            }
            i++;
        }
        f->ptr = r->buf + start;
        f->len = i - start;
        f->quoted = 1;
        i++;                                /* closing quote */
        if (i < r->len && r->buf[i] == '\r')
            i++;
    } else {
        start = i;
        while (i < r->len && r->buf[i] != ',' && r->buf[i] != '\n')
            i++;
        f->ptr = r->buf + start;
        f->len = i - start;
        if (f->len > 0 && f->ptr[f->len - 1] == '\r')
            f->len--;
    }

    if (i >= r->len || r->buf[i] == '\n') {
        f->last_in_row = 1;
        if (i < r->len)
            i++;
    } else if (r->buf[i] == ',') {
        i++;
    } else {
        return -1;                          /* garbage after closing quote */
    }
    r->pos = i;
    return 1;
}
