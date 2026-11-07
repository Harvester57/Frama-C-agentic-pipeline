#include <stdio.h>
#include <string.h>
#include "record.h"

static uint8_t buf[1 << 16];

/* Calls rec_get_<name> through token pasting. */
#define PRINT_FIELD(r, name) \
    printf("  " #name "=%lu\n", (unsigned long)rec_get_##name(r))

int main(int argc, char **argv)
{
    struct record rec;
    size_t n, off = 0;
    int r;

    if (argc > 1 && strcmp(argv[1], "-v") == 0)
        rec_set_verbose(1);
    n = fread(buf, 1, sizeof buf, stdin);
    while (off < n) {
        r = rec_decode(buf + off, n - off, &rec);
        if (r < 0) {
            fprintf(stderr, "bad record at offset %lu\n", (unsigned long)off);
            return 1;
        }
        printf("record @%lu\n", (unsigned long)off);
        PRINT_FIELD(&rec, version);
        PRINT_FIELD(&rec, flags);
        PRINT_FIELD(&rec, length);
        PRINT_FIELD(&rec, seq);
        off += (size_t)r;
    }
    return 0;
}
