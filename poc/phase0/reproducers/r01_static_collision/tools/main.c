#include <stdio.h>
#include "kv.h"

static char inbuf[65536];

/* Third static helper sharing a name with one in the library. */
static void put(const char *s, size_t n)
{
    fwrite(s, 1, n, stdout);
    fputc('\n', stdout);
}

int main(int argc, char **argv)
{
    FILE *f = stdin;
    size_t len, pos = 0, n;
    struct kv_pair p;
    char line[512];
    int r;

    if (argc > 1) {
        f = fopen(argv[1], "rb");
        if (!f) {
            perror(argv[1]);
            return 1;
        }
    }
    len = fread(inbuf, 1, sizeof inbuf, f);
    if (f != stdin)
        fclose(f);

    while ((r = kv_next(inbuf, len, &pos, &p)) > 0) {
        n = kv_emit(&p, line, sizeof line);
        put(line, n);
    }
    if (r < 0) {
        fprintf(stderr, "parse error at offset %lu\n", (unsigned long)pos);
        return 2;
    }
    return 0;
}
