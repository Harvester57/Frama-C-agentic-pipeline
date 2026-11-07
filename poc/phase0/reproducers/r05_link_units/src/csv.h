#ifndef CSV_H
#define CSV_H

#include <stddef.h>

/* RFC 4180-ish CSV reader. Field pointers alias the input buffer. */
struct csv_reader {
    const char *buf;
    size_t len;
    size_t pos;
};

struct csv_field {
    const char *ptr;
    size_t len;
    int quoted;        /* ptr/len still contain doubled quotes */
    int last_in_row;
};

void csv_init(struct csv_reader *r, const char *buf, size_t len);
/* 1 = field read, 0 = end of input, -1 = syntax error */
int csv_next_field(struct csv_reader *r, struct csv_field *f);

size_t csv_field_copy(const struct csv_field *f, char *out, size_t cap);
long csv_field_to_long(const struct csv_field *f, int *ok);

size_t csv_unquote(const char *s, size_t n, char *out, size_t cap);
int csv_needs_quote(const char *s, size_t n);
size_t csv_quote(const char *s, size_t n, char *out, size_t cap);

#endif
