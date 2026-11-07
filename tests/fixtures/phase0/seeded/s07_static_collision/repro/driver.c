/* Repro driver (not built by make). Byte 0 selects the API function; the
 * rest, copied to an exact-size heap buffer, is its input. Scalar
 * parameters take the next input byte. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "frame.h"

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
    switch (data[0] % 5) {
    case 0:
        printf("frame_parse=%ld\n", frame_parse(in, len - 1));
        break;
    case 1:
        printf("frame_digest=%d\n", frame_digest(in, len - 1));
        break;
    case 2:
        printf("frame_payload_sum=%ld\n", frame_payload_sum(in, len - 1));
        break;
    case 3: {
        uint8_t name[8];
        printf("frame_kind_name=%zu\n", frame_kind_name(name, sizeof name, in, len - 1));
        break;
    }
    default:
        if (len >= 2)
            printf("frame_stats=%zu\n", frame_stats(in[0], in + 1, len - 2));
        break;
    }
    free(in);
    return 0;
}
