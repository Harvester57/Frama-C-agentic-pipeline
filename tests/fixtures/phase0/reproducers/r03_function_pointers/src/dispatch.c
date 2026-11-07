#include <stdlib.h>
#include <string.h>
#include "handlers.h"

struct entry {
    uint8_t op;
    const char *name;
    int (*fn)(const struct msg *m, struct sink *out);
};

/* Sorted by op for bsearch. */
static const struct entry table[] = {
    { 0x01, "ping", h_ping },
    { 0x02, "echo", h_echo },
    { 0x10, "sum",  h_sum  },
};

#define NENTRIES (sizeof table / sizeof table[0])

static int cmp_op(const void *key, const void *elem)
{
    int op = *(const uint8_t *)key;
    const struct entry *e = elem;
    return op - (int)e->op;
}

static int cmp_name(const void *a, const void *b)
{
    const char *const *x = a;
    const char *const *y = b;
    return strcmp(*x, *y);
}

int proto_parse(const uint8_t *buf, size_t n, struct msg *m)
{
    if (n < 2)
        return -1;
    m->op = buf[0];
    m->len = buf[1];
    if ((size_t)m->len + 2 > n)
        return -1;
    m->data = buf + 2;
    return 2 + m->len;
}

int proto_dispatch(const struct msg *m, struct sink *out)
{
    const struct entry *e = bsearch(&m->op, table, NENTRIES, sizeof table[0], cmp_op);
    if (!e)
        return -1;
    return e->fn(m, out);
}

int proto_list_ops(struct sink *out)
{
    const char *names[NENTRIES];
    size_t i;

    for (i = 0; i < NENTRIES; i++)
        names[i] = table[i].name;
    qsort(names, NENTRIES, sizeof names[0], cmp_name);
    for (i = 0; i < NENTRIES; i++)
        if (out->write(out->ctx, names[i], strlen(names[i])) < 0)
            return -1;
    return 0;
}
