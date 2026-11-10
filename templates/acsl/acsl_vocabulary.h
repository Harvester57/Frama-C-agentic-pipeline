/*
 * Canonical ACSL Vocabulary Definitions
 *
 * Provides standard specifications for C string validity, buffer validity,
 * ASCII printability, CRLF/NUL injection prevention, and buffer zeroization.
 * Automatically included under __FRAMAC__ via fc_compat_types.h so that
 * all analysis plugins (Eva, WP, E-ACSL) share canonical predicate profiles.
 *
 * Strings (plan step S8): one name per notion, __fc_libc's own. Write these, and only these:
 *
 *   notion                                   canonical name             E-ACSL executes it
 *   readable NUL-terminated string           valid_read_string(s)       yes, NUL within 65536 bytes
 *   writable NUL-terminated string           valid_string(s)            yes, NUL within 65536 bytes
 *   n readable bytes, or a shorter string    valid_read_nstring(s, n)   yes
 *   null or a writable string                valid_string_or_null(s)    yes
 *   length of a string                       strlen(s)                  yes, recursive
 *   string without CR or LF before its NUL   no_crlf_string(s)          yes, through strlen
 *
 * Eva and WP take the predicates and `strlen` from __fc_libc's __fc_string_axiomatic.h, included
 * below; E-ACSL builds take executable definitions of the same names from fc_compat_types.h (its
 * comment lists where an E-ACSL run differs). `\strlen` is not a Frama-C built-in: write `strlen`.
 * `valid_c_string` and `c_strlen` are kept only so contracts written with them still parse: they
 * are `valid_read_string` and `strlen` under another name. Do not write them.
 *
 * Buffers (no NUL involved): valid_read_buffer, valid_write_buffer, no_crlf_or_nul (a length-bounded
 * buffer without CR, LF or NUL), buffer_is_zeroed.
 */

#ifndef ACSL_VOCABULARY_H
#define ACSL_VOCABULARY_H

#if !defined(__FRAMAC_EACSL__)
#include "__fc_string_axiomatic.h"
#endif

/*@
  logic integer c_strlen(char *s) = strlen(s);

  predicate valid_c_string(char *s) = valid_read_string(s);

  predicate no_crlf_string(char *s) =
    \forall integer i; 0 <= i < strlen(s) ==> (s[i] != '\r' && s[i] != '\n');

  predicate valid_read_buffer(char *buf, integer len) =
    len >= 0 && (len == 0 || (buf != \null && \valid_read(buf + (0 .. len - 1))));

  predicate valid_read_buffer(unsigned char *buf, integer len) =
    len >= 0 && (len == 0 || (buf != \null && \valid_read(buf + (0 .. len - 1))));

  predicate valid_write_buffer(char *buf, integer len) =
    len >= 0 && (len == 0 || (buf != \null && \valid(buf + (0 .. len - 1))));

  predicate valid_write_buffer(unsigned char *buf, integer len) =
    len >= 0 && (len == 0 || (buf != \null && \valid(buf + (0 .. len - 1))));

  predicate is_printable_ascii(char c) =
    (0x20 <= c <= 0x7E);

  predicate no_crlf_or_nul(char *buf, integer len) =
    \forall integer k; 0 <= k < len ==>
      (buf[k] != '\r' && buf[k] != '\n' && buf[k] != '\0');

  predicate buffer_is_zeroed(unsigned char *buf, integer len) =
    \forall integer k; 0 <= k < len ==> buf[k] == 0;
*/

#endif /* ACSL_VOCABULARY_H */
