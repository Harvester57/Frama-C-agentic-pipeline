#include <stdio.h>
#include "record.h"
#include "log.h"

static int verbose;

void rec_set_verbose(int on)
{
    verbose = on;
}

int rec_log_fail(const char *func, const char *what)
{
    if (verbose)
        fprintf(stderr, "%s: %s\n", func, what);
    return -1;
}
