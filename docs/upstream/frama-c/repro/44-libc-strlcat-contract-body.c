/* Issue 44: a byte-loop strlcat with the behaviour of the BSD manual and of glibc >= 2.38. WP must
 * prove it against the contract of Frama-C's <string.h>, which comes with the declaration.
 * The one admitted fact is outside WP's memory model. */
#include <stdint.h>
#include <string.h>

size_t strlcat(char *dest, const char *src, size_t n) {
  size_t src_length = strlen(src);
  /* Two separate objects in one address space: their lengths cannot add up past SIZE_MAX. */
  //@ admit no_wrap: strlen(dest) + src_length <= SIZE_MAX;
  size_t d = 0;
  /*@ loop invariant bound: 0 <= d <= n;
      loop invariant in_string: d <= strlen(dest);
      loop invariant no_nul: \forall integer k; 0 <= k < d ==> dest[k] != '\0';
      loop assigns d;
      loop variant n - d; */
  while (d < n && dest[d] != '\0')
    d++;
  if (d == n)
    return n + src_length; /* no NUL within n bytes: nothing is written */
  //@ assert dest_length: d == strlen(dest);
  size_t room = n - d - 1;
  size_t copied = src_length < room ? src_length : room;
  /*@ loop invariant bound: 0 <= i <= copied;
      loop assigns i, dest[d .. d + copied - 1];
      loop variant copied - i; */
  for (size_t i = 0; i < copied; i++)
    dest[d + i] = src[i];
  dest[d + copied] = '\0';
  return d + src_length;
}
