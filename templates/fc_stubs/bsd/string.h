/*
 * Frama-C prototypes and ACSL contracts for <bsd/string.h> (libbsd).
 *
 * strlcpy and strlcat come from ../fc_strlcpy.h, shared with ../fc_compat_types.h because
 * glibc and Frama-C's libc declare them in <string.h> too; its header comment explains the two
 * versions of each contract (strict for Eva and WP, exact for E-ACSL) and the E-ACSL limits
 * behind them. strnstr follows the same rules.
 *
 * No C bodies: Eva and WP use the contracts, which the ledger records as assumed
 * (STATUS_ASSUMED).
 */

#ifndef FRAMAC_BSD_STRING_H
#define FRAMAC_BSD_STRING_H

#include <stddef.h>
#include <string.h>
#include <fc_strlcpy.h>

#if defined(__FRAMAC_EACSL__)

/*@
  // strnstr reads big up to its NUL or len bytes, whichever comes first.
  predicate __fc_bsd_nul_before(char *s, integer len, integer i) = i < len && s[i] == '\0';
*/

/*@
  requires little_string: \valid_read(little) ==>
    \exists integer i; 0 <= i < \block_length(little) - \offset(little) &&
      __fc_bsd_nul_in_block((char *)little, i);
  requires big_readable: (len > 0 && \valid_read(big)) ==>
    (\valid_read(big + (0 .. len - 1)) ||
     \exists integer i; 0 <= i < \block_length(big) - \offset(big) &&
       __fc_bsd_nul_before((char *)big, len, i));
  assigns \result \from big, indirect:big[0 .. len - 1], indirect:little[0 ..], indirect:len;
*/
char *strnstr(const char *big, const char *little, size_t len);

#else /* Eva / WP: Frama-C's libc (valid_read_string, valid_read_nstring) */

/*@
  requires valid_little: valid_read_string(little);
  requires valid_big: valid_read_nstring((char *)big, len);
  terminates \true;
  exits \false;
  assigns \result \from big, indirect:big[0 .. len - 1], indirect:little[0 .. strlen(little)],
                        indirect:len;
  ensures null_or_in_big: \result == \null || \subset(\result, big + (0 .. len));
*/
char *strnstr(const char *big, const char *little, size_t len);

#endif /* __FRAMAC_EACSL__ */

#endif /* FRAMAC_BSD_STRING_H */
