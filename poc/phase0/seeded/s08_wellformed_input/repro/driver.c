/* Repro driver (not built by make). Byte 0 selects the API function; the
 * rest, copied to an exact-size heap buffer, is its input. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sdf.h"

int main(int argc, char **argv)
{
    static uint8_t data[1 << 16];
    uint8_t *in;
    size_t len;
    FILE *f;

    if (argc != 2 || (f = fopen(argv[1], "rb")) == NULL)
        return 2;
    len = fread(data, 1, sizeof data, f);
    fclose(f);
    if (len < 1)
        return 0;
    in = malloc(len - 1 ? len - 1 : 1);
    if (in == NULL)
        return 2;
    memcpy(in, data + 1, len - 1);
    switch (data[0] % 2) {
    case 0:
        printf("sdf_parse=%d\n", sdf_parse(in, len - 1));
        break;
    default:
        printf("sdf_checksum=%u\n", (unsigned)sdf_checksum(in, len - 1));
        break;
    }
    free(in);
    return 0;
}
