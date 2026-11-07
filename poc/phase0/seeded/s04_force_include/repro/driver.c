/* Repro driver (not built by make). Byte 0 selects the API function; the
 * rest, copied to an exact-size heap buffer, is its input. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tlv.h"

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
        printf("tlv_parse=%d\n", tlv_parse(in, len - 1));
        break;
    case 1:
        printf("tlv_get_name=%zu\n", tlv_get_name(out, 64, in, len - 1));
        break;
    default:
        printf("tlv_get_id=%ld\n", tlv_get_id(in, len - 1));
        break;
    }
    free(out);
    free(in);
    return 0;
}
