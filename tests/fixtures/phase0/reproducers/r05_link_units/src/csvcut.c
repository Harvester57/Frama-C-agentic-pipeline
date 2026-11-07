/* csvcut 2,0,3: re-emit the selected columns of stdin, in the given order. */
#include <stdio.h>
#include <stdlib.h>
#include "csv.h"

#define MAX_COLS 16
#define MAX_ROW_FIELDS 64

static char input[1 << 16];

static int parse_cols(const char *spec, unsigned *cols, int max)
{
    int n = 0;
    char *end;

    while (*spec) {
        unsigned long c = strtoul(spec, &end, 10);
        if (end == spec || n >= max || c >= MAX_ROW_FIELDS)
            return -1;
        cols[n++] = (unsigned)c;
        spec = end;
        if (*spec == ',')
            spec++;
        else if (*spec)
            return -1;
    }
    return n;
}

static void emit_row(struct csv_field *row, unsigned nfields, const unsigned *cols, int ncols)
{
    char plain[256], quoted[520];
    int i;

    for (i = 0; i < ncols; i++) {
        if (i)
            putchar(',');
        if (cols[i] < nfields) {
            size_t n = csv_field_copy(&row[cols[i]], plain, sizeof plain);
            csv_quote(plain, n, quoted, sizeof quoted);
            fputs(quoted, stdout);
        }
    }
    putchar('\n');
}

int main(int argc, char **argv)
{
    struct csv_reader r;
    struct csv_field row[MAX_ROW_FIELDS];
    unsigned cols[MAX_COLS], nfields = 0;
    int ncols, rc;
    size_t len;

    if (argc != 2 || (ncols = parse_cols(argv[1], cols, MAX_COLS)) <= 0) {
        fprintf(stderr, "usage: csvcut COL[,COL...] < file.csv\n");
        return 1;
    }
    len = fread(input, 1, sizeof input, stdin);
    csv_init(&r, input, len);
    while ((rc = csv_next_field(&r, &row[nfields])) > 0) {
        int last = row[nfields].last_in_row;
        if (nfields + 1 < MAX_ROW_FIELDS)
            nfields++;
        if (last) {
            emit_row(row, nfields, cols, ncols);
            nfields = 0;
        }
    }
    if (rc < 0) {
        fprintf(stderr, "csvcut: malformed input\n");
        return 2;
    }
    return 0;
}
