/* SYNTHETIC: a global overflow in one function, for tests/test_failure_fixtures_docker.py. Not from a real target. */

int table[8];

static int global_overflow(int i)
{
    return table[i];
}

int main(int argc, char **argv)
{
    (void)argv;
    return global_overflow(8 + argc - 1) != 0;
}
