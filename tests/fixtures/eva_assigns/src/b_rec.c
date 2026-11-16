int depth(int n)
{
    if (n <= 0)
        return 0;
    return 1 + depth(n - 1);
}

int eva_main(void)
{
    volatile int n = 3;
    return depth(n);
}
