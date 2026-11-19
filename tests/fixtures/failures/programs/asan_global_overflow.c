/* SYNTHETIC: a global overflow in one function, for tests/test_failure_fixtures_docker.py. Not from a real target. */

int table[8];

/* Through a pointer: UBSan's bounds check reports an index into the declared array first, and ASan never would. */
static int global_overflow(int i)
{
    const int *p = table;
    return p[i];
}

int main(int argc, char **argv)
{
    (void)argv;
    return global_overflow(8 + argc - 1) != 0;
}
