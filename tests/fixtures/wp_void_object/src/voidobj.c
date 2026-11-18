/* Where WP prints `Warning: void object`, and where it does not (tests/test_wp_void_object.py). */
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>

char buf[8];
char big[32];

struct holder {
    void *ctx;
};

/* False: buf has 8 bytes. WP sizes the void object like an int and proves it under Typed. */
/*@ assigns \nothing; */
void bl_false(void)
{
    void *p = buf;
    /*@ assert bl32: \block_length(p) == 32; */
}

/* The same question asked through a char pointer: no warning, and the true size is proved. */
/*@ assigns \nothing; */
void bl_cast(void)
{
    void *p = buf;
    /*@ assert bl8: \block_length((char *)p) == 8; */
}

/* False: p + 4 is big + 4. Under Bytes the shift of a void pointer steps by 4 bytes. */
/*@ assigns \nothing; */
void shift_false(void)
{
    void *p = big;
    /*@ assert sh16: (char *)(p + 4) == big + 16; */
}

/* False: mempcpy returns d + 2. Its libc contract says `\result == dest + n` on void pointers. */
/*@ requires \valid(d + (0 .. 15));
    requires \valid_read(s + (0 .. 1));
    requires \separated(d + (0 .. 15), s + (0 .. 1));
    assigns d[0 .. 1];
*/
void mempcpy_false(char *d, const char *s)
{
    void *r = mempcpy(d, s, 2);
    /*@ assert mp8: (char *)r == d + 8; */
}

/* Correct code and contract: the warning comes from the pointer_value alarm on the loaded void pointer. */
/*@ requires \valid_read(h);
    assigns \nothing;
    ensures \result == h->ctx;
*/
void *load_void(const struct holder *h)
{
    return h->ctx;
}

/* Correct code and contract: the warning is located at the libc declaration of send. */
/*@ requires \valid_read(b + (0 .. 3));
    requires 0 <= fd < 1024;
*/
long calls_send(int fd, const char *b)
{
    return send(fd, b, 4, 0);
}

/* Takes, stores and passes a void pointer, and writes through it after a cast: no warning. */
/*@ requires \valid(h);
    assigns h->ctx;
    ensures h->ctx == p;
*/
void stores_void(struct holder *h, void *p)
{
    h->ctx = p;
}

/*@ requires \valid((char *)dst + (0 .. n - 1));
    assigns ((char *)dst)[0 .. n - 1];
    ensures \forall integer k; 0 <= k < n ==> ((char *)dst)[k] == 0;
*/
void fill_void(void *dst, size_t n)
{
    char *d = dst;
    /*@ loop invariant 0 <= i <= n;
        loop invariant \forall integer k; 0 <= k < i ==> d[k] == 0;
        loop assigns i, d[0 .. n - 1];
        loop variant n - i;
    */
    for (size_t i = 0; i < n; i++)
        d[i] = 0;
}
