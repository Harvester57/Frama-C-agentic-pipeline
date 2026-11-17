/* SYNTHETIC: a double free in one function, for tests/test_failure_fixtures_docker.py. Not from a real target. */
#include <stdlib.h>

static void release_twice(int *p)
{
    free(p);
    free(p);
}

int main(int argc, char **argv)
{
    int *p = malloc(4 * sizeof(int));
    (void)argv;
    p[0] = argc;
    release_twice(p);
    return 0;
}
