/*
 * Frama-C Bodyless Prototype & ACSL Contract Stub for <bsd/string.h>
 *
 * Used by Frama-C (Eva / WP) under -nostdinc so calls to libbsd string routines
 * are checked for buffer validity and recorded as Considered valid (STATUS_ASSUMED)
 * in the coverage ledger without C stub bodies.
 */

#ifndef FRAMAC_BSD_STRING_H
#define FRAMAC_BSD_STRING_H

#include <stddef.h>
#include <string.h>

/*@
  requires valid_src: src != \null;
  requires valid_dst: size > 0 ==> (dst != \null && \valid(dst + (0 .. size - 1)));
  terminates \true;
  exits \false;
  assigns dst[0 .. size - 1];
  ensures init_dst: size > 0 ==> \initialized(dst);
*/
size_t strlcpy(char *dst, const char *src, size_t size);

/*@
  requires valid_src: src != \null;
  requires valid_dst: size > 0 ==> (dst != \null && \valid(dst + (0 .. size - 1)));
  terminates \true;
  exits \false;
  assigns dst[0 .. size - 1];
*/
size_t strlcat(char *dst, const char *src, size_t size);

/*@
  requires valid_big: big != \null;
  requires valid_little: little != \null;
  terminates \true;
  exits \false;
  assigns \nothing;
  ensures null_or_in_big: \result == \null || \base_addr(\result) == \base_addr(big);
*/
char *strnstr(const char *big, const char *little, size_t len);

#endif /* FRAMAC_BSD_STRING_H */
