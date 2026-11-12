/*
 * Frama-C prototypes and ACSL contracts for strlcpy and strlcat.
 *
 * libbsd declares them in <bsd/string.h>; glibc >= 2.38 and Frama-C 35's libc declare them in
 * <string.h>, with the same prototypes. Included by ./bsd/string.h (Eva, WP and E-ACSL) and by
 * ./fc_compat_types.h (Eva and WP), which first renames the libc declarations: two
 * declarations with contracts are merged by the kernel, and the libc's strlcat contract
 * (`\result == strlen(dest) + strlen(src)` in the post-state, `assigns dest[strlen(dest)..n]`)
 * would be conjoined with this one.
 *
 * No C bodies: Eva and WP use the contracts below, which the ledger records as assumed
 * (STATUS_ASSUMED). Two versions (docs/plans/templates-and-stubs-improvement-plan.md, S4 and
 * decision 1):
 *
 *   Eva / WP (__fc_libc): strict. `dst` must be valid for all `size` bytes, as the BSD manual
 *   asks, so a `size` larger than the buffer is an alarm even when the copy would happen to fit.
 *   Sources must be valid strings; strlcat's `dst` must hold a string within `size`.
 *
 *   E-ACSL (__FRAMAC_EACSL__, checked at run time against the real library): exact. Only the
 *   bytes the call reads or writes must be valid, so a failed precondition is always a real
 *   out-of-bounds access. Three E-ACSL limits shape these clauses:
 *     - Memory an uninstrumented library allocated (glibc's strdup, getenv, json-c) is not
 *       tracked, so `\valid_read` is false on it. Every clause that reads a source string is
 *       guarded by `\valid_read(src) ==>`: an untracked source is not checked rather than
 *       reported. A source pointer that is already out of bounds is missed the same way.
 *     - E-ACSL 35 drops the first conjunct after the guard of `\exists i; a <= i < b && P && Q`
 *       (only Q is checked). Each quantifier body below is therefore one predicate call.
 *     - Logic `strlen` does not exist in host-header mode. Lengths are found by a search
 *       bounded by the source's own block (`\block_length - \offset`), which also keeps a huge
 *       `size` (SIZE_MAX after an underflow) from looping.
 *   Postconditions are Eva / WP only.
 */

#ifndef FRAMAC_FC_STRLCPY_H
#define FRAMAC_FC_STRLCPY_H

#include <stddef.h>

#if defined(__FRAMAC_EACSL__)

/*@
  // s[i] is a NUL inside s's own block.
  predicate __fc_bsd_nul_in_block(char *s, integer i) = s[i] == '\0';

  // strlcpy(dst, src, size) writes dst[0 .. i], where i = min(strlen(src), size - 1).
  predicate __fc_bsd_cpy_fits(char *dst, char *src, integer size, integer i) =
    i < size && (i == size - 1 || src[i] == '\0') && \valid(dst + (0 .. i));

  // strlcat(dst, src, size) with strlen(dst) == d writes dst[d .. d + m],
  // where d + m = min(d + strlen(src), size - 1).
  predicate __fc_bsd_cat_tail_fits(char *dst, char *src, integer size, integer d, integer m) =
    d + m < size && (d + m == size - 1 || src[m] == '\0') && \valid(dst + (d .. d + m));

  predicate __fc_bsd_cat_fits(char *dst, char *src, integer size, integer d) =
    d < size && dst[d] == '\0' &&
    (!\valid_read(src) ||
     \exists integer m; 0 <= m < \block_length(src) - \offset(src) &&
       __fc_bsd_cat_tail_fits(dst, src, size, d, m));
*/

/*@
  requires src_string: \valid_read(src) ==>
    \exists integer i; 0 <= i < \block_length(src) - \offset(src) &&
      __fc_bsd_nul_in_block((char *)src, i);
  requires dst_holds_copy: size > 0 ==>
    (\valid(dst + (0 .. size - 1)) || !\valid_read(src) ||
     \exists integer i; 0 <= i < \block_length(src) - \offset(src) &&
       __fc_bsd_cpy_fits(dst, (char *)src, size, i));
  assigns dst[0 .. size - 1] \from src[0 ..], indirect:size;
  assigns \result \from indirect:src[0 ..];
*/
size_t strlcpy(char *dst, const char *src, size_t size);

/*@
  requires src_string: \valid_read(src) ==>
    \exists integer i; 0 <= i < \block_length(src) - \offset(src) &&
      __fc_bsd_nul_in_block((char *)src, i);
  requires dst_holds_append: size > 0 ==>
    (\valid(dst + (0 .. size - 1)) ||
     \exists integer d; 0 <= d < \block_length(dst) - \offset(dst) &&
       __fc_bsd_cat_fits(dst, (char *)src, size, d));
  assigns dst[0 .. size - 1] \from dst[0 .. size - 1], src[0 ..], indirect:size;
  assigns \result \from indirect:dst[0 .. size - 1], indirect:src[0 ..], indirect:size;
*/
size_t strlcat(char *dst, const char *src, size_t size);

#else /* Eva / WP: Frama-C's libc (valid_read_string, strlen) */

/* Index of the NUL a call writes: min(strlen(src), size - 1) for strlcpy, min(strlen(dst) +
 * strlen(src), size - 1) for strlcat. Spelled as a conditional, not \min: Eva evaluates the
 * conditional when it reduces the post-state (dst[i] == '\0'), and not \min. */

/*@
  requires valid_src: valid_read_string(src);
  requires valid_dst: size > 0 ==> \valid(dst + (0 .. size - 1));
  requires separation: size > 0 ==>
    \separated(dst + (0 .. (strlen(src) < size ? strlen(src) : size - 1)),
               src + (0 .. strlen(src)));
  terminates \true;
  exits \false;
  assigns dst[0 .. (strlen(src) < size ? strlen(src) : size - 1)]
    \from src[0 .. strlen(src)], indirect:size;
  assigns \result \from indirect:src[0 .. strlen(src)];
  ensures result_is_src_length: \result == strlen(src);
  ensures copied: size > 0 ==>
    \forall integer i; 0 <= i < (strlen(src) < size ? strlen(src) : size - 1) ==>
      dst[i] == src[i];
  ensures initialized: size > 0 ==>
    \initialized(dst + (0 .. (strlen(src) < size ? strlen(src) : size - 1)));
  ensures nul_terminated: size > 0 ==>
    dst[strlen(src) < size ? strlen(src) : size - 1] == '\0';
*/
size_t strlcpy(char *dst, const char *src, size_t size);

/*@
  requires valid_src: valid_read_string(src);
  requires dst_string_within_size: valid_read_string(dst) && strlen(dst) < size;
  requires valid_dst: \valid(dst + (0 .. size - 1));
  requires separation: \separated(dst + (0 .. size - 1), src + (0 .. strlen(src)));
  terminates \true;
  exits \false;
  assigns dst[strlen(dst) .. (strlen(dst) + strlen(src) < size ? strlen(dst) + strlen(src)
                                                                 : size - 1)]
    \from src[0 .. strlen(src)], indirect:dst[0 .. strlen(dst)], indirect:size;
  assigns \result \from indirect:dst[0 .. strlen(dst)], indirect:src[0 .. strlen(src)];
  ensures result_is_total_length: \result == \old(strlen(dst)) + strlen(src);
  ensures initialized:
    \initialized(dst + (0 .. (\old(strlen(dst)) + strlen(src) < size
                              ? \old(strlen(dst)) + strlen(src) : size - 1)));
  ensures nul_terminated:
    dst[\old(strlen(dst)) + strlen(src) < size ? \old(strlen(dst)) + strlen(src)
                                               : size - 1] == '\0';
*/
size_t strlcat(char *dst, const char *src, size_t size);

#endif /* __FRAMAC_EACSL__ */

#endif /* FRAMAC_FC_STRLCPY_H */
