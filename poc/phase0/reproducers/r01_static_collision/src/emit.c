#include "kv.h"

/* Same name as the helper in lexer.c, different signature and meaning:
 * returns the NUMBER of leading blanks in s[0..n). */
static size_t skip_ws(const char *s, size_t n)
{
    size_t i = 0;
    while (i < n && (s[i] == ' ' || s[i] == '\t'))
        i++;
    return i;
}

/* Appends one byte, always keeping room for the terminating NUL. */
static int put(char *out, size_t cap, size_t *o, char c)
{
    if (*o + 1 >= cap)
        return -1;
    out[(*o)++] = c;
    return 0;
}

size_t kv_emit(const struct kv_pair *p, char *out, size_t cap)
{
    size_t o = 0, i;

    if (cap == 0)
        return 0;
    for (i = 0; i < p->key_len; i++)
        if (put(out, cap, &o, p->key[i]))
            goto done;
    if (put(out, cap, &o, '=') || put(out, cap, &o, '"'))
        goto done;
    for (i = skip_ws(p->val, p->val_len); i < p->val_len; i++) {
        char c = p->val[i];
        if (c == '"' || c == '\\')
            if (put(out, cap, &o, '\\'))
                goto done;
        if (put(out, cap, &o, c))
            goto done;
    }
    put(out, cap, &o, '"');
done:
    out[o] = '\0';
    return o;
}
