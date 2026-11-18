/* Reference bodies for strlcpy and strlcat: plain byte loops with the behaviour the BSD manual
 * documents. tests/test_fc_strlcpy_reference.py proves them with WP against the Eva / WP contracts
 * of templates/fc_stubs/fc_strlcpy.h (the contracts come from the declarations: fc_compat_types.h
 * is force-included), and differential.c compares them with the C library's functions.
 *
 * The `admit` clauses are the facts the proof needs and the contracts do not state. The test pins
 * their names: a new one means a contract claims more than it says. */
#include <stdint.h>
#include <string.h>

size_t strlcpy(char *dst, const char *src, size_t size) {
  size_t src_length = strlen(src);
  /* valid_read_string says nothing about initialization under WP, and WP gives a copied byte the
   * initialization status of its source. */
  //@ admit src_initialized: \initialized(src + (0 .. src_length));
  //@ assert src_nul: src[src_length] == '\0';
  //@ assert src_no_nul: \forall integer k; 0 <= k < src_length ==> src[k] != '\0';
  if (size > 0) {
    size_t n = src_length < size ? src_length : size - 1;
    size_t i;
    /*@ loop invariant bound: 0 <= i <= n;
        loop invariant copied: \forall integer k; 0 <= k < i ==> dst[k] == src[k];
        loop invariant init: \forall integer k; 0 <= k < i ==> \initialized(dst + k);
        loop assigns i, dst[0 .. n - 1];
        loop variant n - i; */
    for (i = 0; i < n; i++)
      dst[i] = src[i];
    dst[n] = '\0';
    //@ assert src_kept: \forall integer k; 0 <= k <= src_length ==> src[k] == \at(src[k], Pre);
    //@ assert src_length_kept: strlen(src) == src_length;
  }
  return src_length;
}

size_t strlcat(char *dst, const char *src, size_t size) {
  size_t src_length = strlen(src);
  //@ admit src_initialized: \initialized(src + (0 .. src_length));
  /* The contract's `ensures initialized` starts at dst[0], which the call only reads. */
  //@ admit dst_initialized: \initialized(dst + (0 .. strlen(dst)));
  /* Two separate objects in one address space: their lengths cannot add up past SIZE_MAX. */
  //@ admit no_wrap: strlen(dst) + src_length <= SIZE_MAX;
  //@ assert src_nul: src[src_length] == '\0';
  //@ assert src_no_nul: \forall integer k; 0 <= k < src_length ==> src[k] != '\0';
  size_t d = 0;
  /*@ loop invariant bound: 0 <= d <= size;
      loop invariant in_string: d <= strlen(dst);
      loop invariant no_nul: \forall integer k; 0 <= k < d ==> dst[k] != '\0';
      loop assigns d;
      loop variant size - d; */
  while (d < size && dst[d] != '\0')
    d++;
  if (d == size)
    return size + src_length; /* no NUL within size: nothing is written (outside the contract) */
  //@ assert dst_length: d == strlen(dst);
  size_t room = size - d - 1;
  size_t n = src_length < room ? src_length : room;
  size_t i;
  /*@ loop invariant bound: 0 <= i <= n;
      loop invariant copied: \forall integer k; 0 <= k < i ==> dst[d + k] == src[k];
      loop invariant init: \forall integer k; d <= k < d + i ==> \initialized(dst + k);
      loop assigns i, dst[d .. d + n - 1];
      loop variant n - i; */
  for (i = 0; i < n; i++)
    dst[d + i] = src[i];
  dst[d + n] = '\0';
  //@ assert src_kept: \forall integer k; 0 <= k <= src_length ==> src[k] == \at(src[k], Pre);
  //@ assert src_length_kept: strlen(src) == src_length;
  //@ assert appended_init: \forall integer k; d <= k <= d + n ==> \initialized(dst + k);
  return d + src_length;
}
