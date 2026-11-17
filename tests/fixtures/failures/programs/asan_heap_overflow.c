/* SYNTHETIC: a heap overflow in one function, for tests/test_failure_fixtures_docker.py. Not from a real target. */
#include <stdlib.h>

static int heap_overflow(int i)
{
    int *a = malloc(4 * sizeof(int));
    int s = a[i];
    free(a);
    return s;
}

int main(int argc, char **argv)
{
    (void)argv;
    return heap_overflow(4 + argc - 1) != 0;
}
