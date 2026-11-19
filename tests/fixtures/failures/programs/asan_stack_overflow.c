/* SYNTHETIC: a stack overflow in one function, for tests/test_failure_fixtures_docker.py. Not from a real target. */

/* Through a pointer: UBSan's bounds check reports an index into the declared array first, and ASan never would. */
static int stack_overflow(int i)
{
    int local[4] = {0, 1, 2, 3};
    const int *p = local;
    return p[i];
}

int main(int argc, char **argv)
{
    (void)argv;
    return stack_overflow(4 + argc - 1) != 0;
}
