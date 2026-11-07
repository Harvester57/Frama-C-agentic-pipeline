#include "api.h"

/* A GNU C nested function: gcc compiles it, Frama-C refuses it, so this unit takes the GCC fallback. */
int nest_sum(int n)
{
    int add(int a) { return a + clamp(n); }
    int s = 0;
    for (int i = 0; i < n; i++)
        s = add(s);
    return s;
}
