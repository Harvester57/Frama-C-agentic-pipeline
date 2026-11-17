/* SYNTHETIC: hand-written fixture source for tests/test_failure_fixtures.py. Not from a real target. */
#include <stdlib.h>
#include <string.h>

int table[8];

int read_slot(int *p, int i)
{
    return p[i];
}

char *make_buf(size_t n)
{
    char *buf = malloc(n);
    if (buf)
        buf[0] = 'x';
    return buf;
}

void copy_block(char *dst, const char *src, size_t n)
{
    memcpy(dst, src, n);
}

int free_then_read(int *p)
{
    free(p);
    return p[0];
}

void release_twice(int *p)
{
    free(p);
    free(p);
}

void release_local(void)
{
    int local[2];
    free(local);
}

int heap_overflow(void)
{
    int *a = malloc(4 * sizeof(int));
    int s = a[4];
    free(a);
    return s;
}

int stack_overflow(void)
{
    int local[4];
    return local[5];
}

int global_overflow(int i)
{
    return table[i];
}

int two_overflows(int *a, int i)
{
    int x = a[i];
    int y = a[i + 9];
    return x + y;
}

int add_wrap(int a, int b)
{
    return a + b;
}

int shift_bits(int v, int s)
{
    return v << s;
}

int abs_min(int v)
{
    return v < 0 ? -v : v;
}

int checked_div(int x, int y)
{
    return x / y;
}

int read_uninit(void)
{
    int v;
    return v + 1;
}
