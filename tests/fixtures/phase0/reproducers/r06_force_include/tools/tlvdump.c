#include <stdio.h>
#include <string.h>
#include "tlv.h"

static uint8_t buf[1 << 16];

int main(int argc, char **argv)
{
    struct tlv_stats st;
    size_t n;

    if (argc > 1 && strcmp(argv[1], "--version") == 0) {
        printf("tlvdump %s\n", tlv_version());
        return 0;
    }
    n = fread(buf, 1, sizeof buf, stdin);
    if (tlv_walk(buf, n, &st) != 0) {
        fprintf(stderr, "malformed TLV input\n");
        return 1;
    }
    printf("elements=%lu constructed=%lu bytes=%lu depth=%d\n",
           st.count, st.constructed, st.bytes, st.max_depth);
    return 0;
}
