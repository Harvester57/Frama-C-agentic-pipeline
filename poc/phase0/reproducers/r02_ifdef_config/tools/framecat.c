#include <stdio.h>
#include "frame.h"
#include "platform.h"

static uint8_t data[1 << 16];

#ifdef DEBUG
static void hexdump(const uint8_t *p, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++)
        fprintf(stderr, "%02x%c", p[i], (i % 16 == 15) ? '\n' : ' ');
    fputc('\n', stderr);
}
#endif

static const char *type_name(uint8_t t)
{
    switch (t & 0x7Fu) {
    case 1: return "hello";
    case 2: return "data";
    case 3: return "bye";
    default: return "?";
    }
}

int main(int argc, char **argv)
{
    size_t n, off = 0;
    struct frame f;
    int r;

    if (argc != 2) {
        fprintf(stderr, "usage: %s FILE\n", argv[0]);
        return 1;
    }
    if (plat_read_file(argv[1], data, sizeof data, &n) != 0) {
        fprintf(stderr, "cannot read %s\n", argv[1]);
        return 1;
    }
    while (off < n) {
        r = frame_decode(data + off, n - off, &f);
        if (r < 0) {
            fprintf(stderr, "bad frame at %lu (%d)\n", (unsigned long)off, r);
            return 2;
        }
        printf("%s len=%u flags=%02x\n", type_name(f.type), (unsigned)f.len,
               (unsigned)f.ext_flags);
#ifdef DEBUG
        hexdump(f.payload, f.len);
#endif
        off += (size_t)r;
    }
    return 0;
}
