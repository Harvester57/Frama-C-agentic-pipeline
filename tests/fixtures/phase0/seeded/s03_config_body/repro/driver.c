/* Repro driver (not built by make). Byte 0 selects the API function; the
 * rest, copied to an exact-size heap buffer, is its input. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pkt.h"

int main(int argc, char **argv)
{
    static uint8_t data[1 << 16];
    uint8_t *in, *out;
    size_t len;
    FILE *f;

    if (argc != 2 || (f = fopen(argv[1], "rb")) == NULL)
        return 2;
    len = fread(data, 1, sizeof data, f);
    fclose(f);
    if (len < 1)
        return 0;
    in = malloc(len - 1 ? len - 1 : 1);
    out = malloc(64);
    if (in == NULL || out == NULL)
        return 2;
    memcpy(in, data + 1, len - 1);
    switch (data[0] % 3) {
    case 0:
        printf("pkt_decode=%d\n", pkt_decode(in, len - 1));
        break;
    case 1:
        printf("pkt_unescape=%zu\n", pkt_unescape(out, 64, in, len - 1));
        break;
    default:
        printf("pkt_escape_cost=%zu\n", pkt_escape_cost(in, len - 1));
        break;
    }
    free(out);
    free(in);
    return 0;
}
