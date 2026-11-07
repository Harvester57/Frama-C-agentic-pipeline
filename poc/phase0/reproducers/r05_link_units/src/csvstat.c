/* csvstat COL: count/sum/min/max of numeric column COL (0-based) on stdin. */
#include <stdio.h>
#include <stdlib.h>
#include "csv.h"

static char input[1 << 16];

static void report(unsigned long col, unsigned long count, long sum, long min, long max)
{
    if (count == 0) {
        printf("column %lu: no numeric values\n", col);
        return;
    }
    printf("column %lu: count=%lu sum=%ld min=%ld max=%ld\n", col, count, sum, min, max);
}

int main(int argc, char **argv)
{
    struct csv_reader r;
    struct csv_field f;
    unsigned long want, col = 0, count = 0;
    long v, sum = 0, min = 0, max = 0;
    size_t len;
    int rc, ok;

    if (argc != 2) {
        fprintf(stderr, "usage: csvstat COL < file.csv\n");
        return 1;
    }
    want = strtoul(argv[1], NULL, 10);
    len = fread(input, 1, sizeof input, stdin);
    csv_init(&r, input, len);
    while ((rc = csv_next_field(&r, &f)) > 0) {
        if (col == want) {
            v = csv_field_to_long(&f, &ok);
            if (ok) {
                if (count == 0 || v < min)
                    min = v;
                if (count == 0 || v > max)
                    max = v;
                sum += v;
                count++;
            }
        }
        col = f.last_in_row ? 0 : col + 1;
    }
    if (rc < 0) {
        fprintf(stderr, "csvstat: malformed input\n");
        return 2;
    }
    report(want, count, sum, min, max);
    return 0;
}
