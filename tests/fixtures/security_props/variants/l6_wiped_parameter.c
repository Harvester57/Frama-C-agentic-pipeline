/* L6_wiped, parameter secret with a size: key[0 .. len - 1] is zero when burn returns. */
#include <stddef.h>

/*@ requires \valid(key + (0 .. len - 1)); */
void burn(unsigned char *key, size_t len)
{
#ifndef VIOLATE
    /*@ loop invariant 0 <= i <= len;
        loop invariant \forall integer j; 0 <= j < i ==> key[j] == 0;
        loop assigns i, key[0 .. len - 1];
        loop variant len - i;
    */
    for (size_t i = 0; i < len; i++)
        key[i] = 0;
#else
    (void)key;
    (void)len;
#endif
}
