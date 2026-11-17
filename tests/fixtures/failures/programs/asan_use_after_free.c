/* SYNTHETIC: a read after free in one function, for tests/test_failure_fixtures_docker.py. Not from a real target. */
#include <stdlib.h>

static int free_then_read(int *p)
{
    free(p);
    return p[0];
}

int main(int argc, char **argv)
{
    int *p = malloc(4 * sizeof(int));
    (void)argv;
    p[0] = argc;
    return free_then_read(p) != 0;
}
