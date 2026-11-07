#include <string.h>

#include "msg.h"
#include "compat.h"

#define TAG_MAX 15

struct field {
    const char *key;
    size_t klen;
    const char *val;
    size_t vlen;
};

/* Splits the next "key=value" field off *s. Returns 0, or -1 at the end. */
static int next_field(const char **s, struct field *f)
{
    const char *p = *s, *eq, *end;

    if (*p == '\0')
        return -1;
    end = strchr(p, ';');
    if (end == NULL)
        end = p + strlen(p);
    eq = memchr(p, '=', (size_t)(end - p));
    f->key = p;
    f->klen = eq ? (size_t)(eq - p) : (size_t)(end - p);
    f->val = eq ? eq + 1 : end;
    f->vlen = (size_t)(end - f->val);
    *s = *end ? end + 1 : end;
    return 0;
}

static int key_is(const struct field *f, const char *k)
{
    return f->klen == strlen(k) && memcmp(f->key, k, f->klen) == 0;
}

static long parse_ip(const struct field *f)
{
    uint8_t ip[4];
    long n = b64_decode(ip, sizeof ip, (const uint8_t *)f->val, f->vlen);

    if (n != 4)
        return -1;
    return (long)load_be32(ip);
}

static long parse_port(const struct field *f)
{
    long port = 0;
    size_t i;

    if (f->vlen == 0)
        return -1;
    for (i = 0; i < f->vlen; i++) {
        if (f->val[i] < '0' || f->val[i] > '9')
            return -1;
        port = port * 10 + (f->val[i] - '0');
        if (port > 65535)
            return -1;
    }
    return port == 0 ? -1 : port;
}

int msg_parse(const char *str)
{
    struct field f;
    char tag[TAG_MAX + 1];
    int known = 0;

    while (next_field(&str, &f) == 0) {
        if (key_is(&f, "ip")) {
            if (parse_ip(&f) < 0)
                return -1;
        } else if (key_is(&f, "port")) {
            if (parse_port(&f) < 0)
                return -1;
        } else if (key_is(&f, "tag")) {
            if (f.vlen > TAG_MAX)
                return -1;
            memcpy(tag, f.val, f.vlen);
            tag[f.vlen] = '\0';
            if (tag[0] == '!')
                return -1;
        } else {
            continue;
        }
        known++;
    }
    return known;
}

long msg_peer_ip(const char *str)
{
    struct field f;

    while (next_field(&str, &f) == 0)
        if (key_is(&f, "ip"))
            return parse_ip(&f);
    return -1;
}

size_t msg_b64(uint8_t *out, size_t cap, const uint8_t *in, size_t len)
{
    long n = b64_decode(out, cap, in, len);

    return n < 0 ? 0 : (size_t)n;
}
