/* SYNTHETIC: two reads in one function, the second out of bounds, for tests/test_failure_fixtures_docker.py. */
#include <stdlib.h>

static int two_overflows(int *a, int i)
{
    int x = a[i];
    int y = a[i + 9];
    return x + y;
}

int main(int argc, char **argv)
{
    int *a = malloc(8 * sizeof(int));
    int r;
    (void)argv;
    r = two_overflows(a, argc - 1);
    free(a);
    return r != 0;
}
