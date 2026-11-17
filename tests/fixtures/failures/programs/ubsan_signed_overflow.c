/* SYNTHETIC: a signed overflow in one function, for tests/test_failure_fixtures_docker.py. Not from a real target. */

static int add_wrap(int a, int b)
{
    return a + b;
}

int main(int argc, char **argv)
{
    (void)argv;
    return add_wrap(2147483647, argc) != 0;
}
