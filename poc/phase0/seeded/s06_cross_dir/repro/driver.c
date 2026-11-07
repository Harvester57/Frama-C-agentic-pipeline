/* Repro driver (not built by make). Byte 0 selects the API function; the
 * rest, copied to an exact-size heap buffer (NUL-terminated for string
 * parameters), is its input. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "msg.h"

int main(int argc, char **argv)
{
    static uint8_t data[1 << 16];
    uint8_t *in, *out;
    char *str;
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
    str = malloc(len);
    if (in == NULL || out == NULL || str == NULL)
        return 2;
    memcpy(in, data + 1, len - 1);
    memcpy(str, data + 1, len - 1);
    str[len - 1] = '\0';
    switch (data[0] % 3) {
    case 0:
        printf("msg_parse=%d\n", msg_parse(str));
        break;
    case 1:
        printf("msg_peer_ip=%ld\n", msg_peer_ip(str));
        break;
    default:
        printf("msg_b64=%zu\n", msg_b64(out, 64, in, len - 1));
        break;
    }
    free(str);
    free(out);
    free(in);
    return 0;
}
