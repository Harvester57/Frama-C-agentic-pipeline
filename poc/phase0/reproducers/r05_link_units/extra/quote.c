/* Quoting helpers: part of libcsv.a although they live outside src/. */
#include "csv.h"

size_t csv_unquote(const char *s, size_t n, char *out, size_t cap)
{
    size_t i, o = 0;

    if (cap == 0)
        return 0;
    for (i = 0; i < n && o + 1 < cap; i++) {
        out[o++] = s[i];
        if (s[i] == '"' && i + 1 < n && s[i + 1] == '"')
            i++;                            /* "" -> " */
    }
    out[o] = '\0';
    return o;
}

int csv_needs_quote(const char *s, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++)
        if (s[i] == ',' || s[i] == '"' || s[i] == '\n' || s[i] == '\r')
            return 1;
    return 0;
}

size_t csv_quote(const char *s, size_t n, char *out, size_t cap)
{
    size_t i, o = 0;

    if (cap == 0)
        return 0;
    if (!csv_needs_quote(s, n)) {
        for (i = 0; i < n && o + 1 < cap; i++)
            out[o++] = s[i];
        out[o] = '\0';
        return o;
    }
    if (cap < 3) {
        out[0] = '\0';
        return 0;
    }
    out[o++] = '"';
    for (i = 0; i < n; i++) {
        size_t need = (s[i] == '"') ? 2 : 1;
        if (o + need + 2 > cap)
            break;
        if (s[i] == '"')
            out[o++] = '"';
        out[o++] = s[i];
    }
    out[o++] = '"';
    out[o] = '\0';
    return o;
}
