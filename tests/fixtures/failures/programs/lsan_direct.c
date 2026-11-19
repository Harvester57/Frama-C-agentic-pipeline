/* SYNTHETIC: a direct leak allocated in one function, for tests/test_failure_fixtures_docker.py. Not from a real target. */
#include <stdlib.h>

static char *make_buf(size_t n)
{
    char *buf = malloc(n);
    if (buf)
        buf[0] = 'x';
    return buf;
}

/*
 * LeakSanitizer scans the stack conservatively, dead frames included: a copy of the pointer left in one makes the
 * block reachable and the leak goes unreported. Not instrumented by ASan, so that `pad` stays on the real stack.
 */
__attribute__((noinline, no_sanitize("address"))) static void clear_dead_frames(void)
{
    volatile char pad[4096];
    for (size_t i = 0; i < sizeof pad; i++)
        pad[i] = 0;
}

int main(int argc, char **argv)
{
    char *b;
    int failed;
    (void)argv;
    b = make_buf(16 * (size_t)argc);
    failed = b == 0;
    b = 0;
    clear_dead_frames();
    return failed;
}
