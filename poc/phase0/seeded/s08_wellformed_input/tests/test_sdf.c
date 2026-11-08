/* Unit tests of the frame parser: the frames are inline literals, sealed with their checksum. */
#include <stdio.h>

#include "sdf.h"

static int failures;

static void seal(uint8_t *f)
{
    uint16_t c = sdf_checksum(f, SDF_HDR_LEN - 2);
    f[10] = (uint8_t)(c & 0xff);
    f[11] = (uint8_t)(c >> 8);
}

static void expect(const char *what, int got, int want)
{
    if (got != want) {
        printf("FAIL %s: %d, expected %d\n", what, got, want);
        failures++;
    }
}

int main(void)
{
    uint8_t full[] = {'S', 'D', 'F', '1', 2, 0, 3, 0, 0, 0, 0, 0,
                      1, 7, 's', 'e', 'n', 's', 'o', 'r', '1',
                      2, 4, 0x10, 0x27, 0, 0,
                      3, 1, 'C'};
    uint8_t value_only[] = {'S', 'D', 'F', '1', 2, 1, 1, 0, 0, 0, 0, 0, 2, 4, 1, 2, 3, 4};
    uint8_t short_name[] = {'S', 'D', 'F', '1', 2, 0, 2, 0, 0, 0, 0, 0, 1, 2, 'o', 'k', 3, 1, 'K'};
    uint8_t bad_version[] = {'S', 'D', 'F', '1', 3, 0, 1, 0, 0, 0, 0, 0, 3, 1, 'C'};
    uint8_t truncated[] = {'S', 'D', 'F', '1', 2, 0, 2, 0, 0, 0, 0, 0, 2, 4, 1, 2};
    uint8_t unsealed[] = {'S', 'D', 'F', '1', 2, 0, 1, 0, 0, 0, 0, 0, 3, 1, 'C'};

    seal(full);
    seal(value_only);
    seal(short_name);
    seal(bad_version);
    seal(truncated);
    expect("full", sdf_parse(full, sizeof full), 3);
    expect("value_only", sdf_parse(value_only, sizeof value_only), 1);
    expect("short_name", sdf_parse(short_name, sizeof short_name), 2);
    expect("bad_version", sdf_parse(bad_version, sizeof bad_version), -1);
    expect("truncated", sdf_parse(truncated, sizeof truncated), -1);
    expect("unsealed", sdf_parse(unsealed, sizeof unsealed), -1);
    expect("empty", sdf_parse(full, 0), -1);
    printf("%s\n", failures ? "FAILED" : "OK");
    return failures != 0;
}
