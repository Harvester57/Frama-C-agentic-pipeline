/* SYNTHETIC: a negation of INT_MIN in one function, for tests/test_failure_fixtures_docker.py. */

static int abs_min(int v)
{
    return v < 0 ? -v : v;
}

int main(int argc, char **argv)
{
    (void)argv;
    return abs_min(-2147483647 - argc) != 0;
}
