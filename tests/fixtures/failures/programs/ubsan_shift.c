/* SYNTHETIC: a left shift of a negative value in one function, for tests/test_failure_fixtures_docker.py. */

static int shift_bits(int v, int s)
{
    return v << s;
}

int main(int argc, char **argv)
{
    (void)argv;
    return shift_bits(-5, argc) != 0;
}
