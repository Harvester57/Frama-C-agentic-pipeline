#include "kv.h"

/* Returns the index of the first non-blank character at or after i. */
static size_t skip_ws(const char *s, size_t len, size_t i)
{
    while (i < len && (s[i] == ' ' || s[i] == '\t'))
        i++;
    return i;
}

static int is_key_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_' || c == '.';
}

int kv_next(const char *buf, size_t len, size_t *pos, struct kv_pair *out)
{
    size_t i = *pos;
    size_t k, v, e;

    /* Skip blank lines and comments. */
    while (i < len) {
        i = skip_ws(buf, len, i);
        if (i < len && (buf[i] == '\n' || buf[i] == '\r' || buf[i] == '#')) {
            while (i < len && buf[i] != '\n')
                i++;
            if (i < len)
                i++;
            continue;
        }
        break;
    }
    if (i >= len) {
        *pos = i;
        return 0;
    }

    k = i;
    while (i < len && is_key_char(buf[i]))
        i++;
    if (i == k)
        return -1;
    out->key = buf + k;
    out->key_len = i - k;

    i = skip_ws(buf, len, i);
    if (i >= len || buf[i] != '=')
        return -1;
    i = skip_ws(buf, len, i + 1);

    v = i;
    while (i < len && buf[i] != '\n')
        i++;
    e = i;
    while (e > v && (buf[e - 1] == ' ' || buf[e - 1] == '\t' || buf[e - 1] == '\r'))
        e--;
    out->val = buf + v;
    out->val_len = e - v;

    if (i < len)
        i++;
    *pos = i;
    return 1;
}
