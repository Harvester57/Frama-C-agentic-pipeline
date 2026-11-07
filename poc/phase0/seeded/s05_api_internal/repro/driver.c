/* Repro driver (not built by make). Byte 0 selects the API function; the
 * rest, copied to an exact-size heap buffer, is its input. Scalar
 * parameters take the next input byte. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kv.h"

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
    switch (data[0] % 5) {
    case 0:
        printf("kv_load=%d\n", kv_load(in, len - 1));
        break;
    case 1:
        printf("kv_find=%d\n", kv_find(str));
        break;
    case 2:
        if (len >= 2)
            printf("kv_key_equals=%d\n", kv_key_equals(in[0], in + 1, len - 2));
        break;
    case 3:
        printf("kv_get=%zu\n", kv_get(out, 64, in, len - 1));
        break;
    default:
        printf("kv_count=%d\n", kv_count());
        break;
    }
    free(str);
    free(out);
    free(in);
    return 0;
}
