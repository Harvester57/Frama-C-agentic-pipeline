/* SYNTHETIC: a direct leak allocated in one function, for tests/test_failure_fixtures_docker.py. Not from a real target. */
#include <stdlib.h>

static char *make_buf(size_t n)
{
    char *buf = malloc(n);
    if (buf)
        buf[0] = 'x';
    return buf;
}

int main(int argc, char **argv)
{
    char *b;
    (void)argv;
    b = make_buf(16 * (size_t)argc);
    return b == 0;
}
