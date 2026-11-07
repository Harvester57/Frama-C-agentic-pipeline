#include <stdio.h>
#include <string.h>
#include "proto.h"

static unsigned char buf[4096];

static int write_plain(void *ctx, const char *s, size_t n)
{
    FILE *f = ctx;
    if (fwrite(s, 1, n, f) != n)
        return -1;
    fputc('\n', f);
    return 0;
}

static int write_hex(void *ctx, const char *s, size_t n)
{
    FILE *f = ctx;
    size_t i;
    for (i = 0; i < n; i++)
        fprintf(f, "%02x", (unsigned char)s[i]);
    fputc('\n', f);
    return 0;
}

int main(int argc, char **argv)
{
    struct sink out;
    struct msg m;
    size_t n, off = 0;
    int i, r, hex = 0, list = 0;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-x") == 0)
            hex = 1;
        else if (strcmp(argv[i], "-l") == 0)
            list = 1;
    }
    out.ctx = stdout;
    out.write = hex ? write_hex : write_plain;

    if (list)
        return proto_list_ops(&out) ? 1 : 0;

    n = fread(buf, 1, sizeof buf, stdin);
    while (off < n && (r = proto_parse(buf + off, n - off, &m)) > 0) {
        if (proto_dispatch(&m, &out) < 0)
            fprintf(stderr, "unknown op 0x%02x\n", (unsigned)m.op);
        off += (size_t)r;
    }
    return 0;
}
