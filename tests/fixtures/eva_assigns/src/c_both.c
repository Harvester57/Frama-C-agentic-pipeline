#include "stub.h"

int depth(int n)
{
    if (n <= 0)
        return 0;
    return 1 + depth(n - 1);
}

int eva_main(void)
{
    volatile int n = 3;
    int x = 0;
    int r = fill(&x);
    return r + x + depth(n);
}
