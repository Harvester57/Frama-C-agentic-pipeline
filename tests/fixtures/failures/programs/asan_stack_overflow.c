/* SYNTHETIC: a stack overflow in one function, for tests/test_failure_fixtures_docker.py. Not from a real target. */

static int stack_overflow(int i)
{
    int local[4] = {0, 1, 2, 3};
    return local[i];
}

int main(int argc, char **argv)
{
    (void)argv;
    return stack_overflow(4 + argc - 1) != 0;
}
