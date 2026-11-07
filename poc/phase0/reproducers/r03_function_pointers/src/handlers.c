#include <stdio.h>
#include "handlers.h"

int h_ping(const struct msg *m, struct sink *out)
{
    (void)m;
    return out->write(out->ctx, "pong", 4);
}

int h_echo(const struct msg *m, struct sink *out)
{
    return out->write(out->ctx, (const char *)m->data, m->len);
}

int h_sum(const struct msg *m, struct sink *out)
{
    unsigned s = 0;
    char b[16];
    int n;
    size_t i;

    for (i = 0; i < m->len; i++)
        s += m->data[i];
    n = snprintf(b, sizeof b, "%u", s);
    if (n < 0)
        return -1;
    return out->write(out->ctx, b, (size_t)n);
}

/* Not registered in the dispatch table (op retired in protocol v2). */
int h_reset(const struct msg *m, struct sink *out)
{
    (void)m;
    (void)out;
    return 0;
}
