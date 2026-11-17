/* SYNTHETIC: a free of a stack object in one function, for tests/test_failure_fixtures_docker.py. Not from a real target. */
#include <stdlib.h>

static void release_local(int n)
{
    int local[2] = {n, n};
    free(local);
}

int main(int argc, char **argv)
{
    (void)argv;
    release_local(argc);
    return 0;
}
