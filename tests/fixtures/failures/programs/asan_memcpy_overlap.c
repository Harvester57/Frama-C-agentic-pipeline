/* SYNTHETIC: an overlapping memcpy in one function, for tests/test_failure_fixtures_docker.py. Not from a real target. */
#include <string.h>

static void copy_block(char *dst, const char *src, size_t n)
{
    memcpy(dst, src, n);
}

int main(int argc, char **argv)
{
    char buf[16] = {0};
    (void)argv;
    copy_block(buf, buf + 4 * (argc > 0), 8);
    return buf[0] != 0;
}
