#include <stdlib.h>
#include <string.h>
#include "csv.h"

size_t csv_field_copy(const struct csv_field *f, char *out, size_t cap)
{
    size_t n;

    if (f->quoted)
        return csv_unquote(f->ptr, f->len, out, cap);
    if (cap == 0)
        return 0;
    n = f->len < cap - 1 ? f->len : cap - 1;
    memcpy(out, f->ptr, n);
    out[n] = '\0';
    return n;
}

long csv_field_to_long(const struct csv_field *f, int *ok)
{
    char tmp[32];
    char *end;
    long v;
    size_t n = csv_field_copy(f, tmp, sizeof tmp);

    if (n == 0 || n >= sizeof tmp - 1) {
        *ok = 0;
        return 0;
    }
    v = strtol(tmp, &end, 10);
    *ok = (*end == '\0');
    return v;
}
