#include <string.h>

#include "proto.h"
#include "handlers.h"

typedef int (*handler_fn)(struct reply *r, const uint8_t *p, size_t n);

struct op_entry {
    uint8_t code;
    const char *name;
    handler_fn fn;
};

/* Registers handler h_<name> under opcode OP_<name>. */
#define HANDLER(name) { OP_##name, #name, h_##name }

static const struct op_entry ops[] = {
    HANDLER(ping),
    HANDLER(echo),
    HANDLER(sum),
    HANDLER(rev),
    HANDLER(upper),
};

static const struct op_entry *find_op(uint8_t code)
{
    size_t i;

    for (i = 0; i < sizeof ops / sizeof ops[0]; i++)
        if (ops[i].code == code)
            return &ops[i];
    return NULL;
}

static int run_op(struct reply *r, const uint8_t *in, size_t len)
{
    const struct op_entry *op;

    if (len < 1)
        return -1;
    op = find_op(in[0]);
    if (op == NULL)
        return -1;
    r->used = 0;
    return op->fn(r, in + 1, len - 1);
}

size_t proto_reply(uint8_t *out, size_t cap, const uint8_t *in, size_t len)
{
    uint8_t scratch[REPLY_MAX];
    struct reply r = { scratch, sizeof scratch, 0 };

    if (run_op(&r, in, len) != 0)
        return 0;
    if (r.used > cap)
        r.used = cap;
    memcpy(out, scratch, r.used);
    return r.used;
}

int proto_run(const uint8_t *buf, size_t len)
{
    uint8_t scratch[REPLY_MAX];
    struct reply r = { scratch, sizeof scratch, 0 };
    size_t pos = 0;
    int ok = 0;

    while (pos < len) {
        size_t n = buf[pos++];
        if (n > len - pos)
            return -1;
        if (run_op(&r, buf + pos, n) == 0)
            ok++;
        pos += n;
    }
    return ok;
}
