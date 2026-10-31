/*
 * Canonical ACSL Vocabulary Definitions
 *
 * Provides standard specifications for C string validity, buffer validity,
 * ASCII printability, CRLF/NUL injection prevention, and buffer zeroization.
 * Automatically included under __FRAMAC__ via fc_compat_types.h so that
 * all analysis plugins (Eva, WP, E-ACSL) share canonical predicate profiles.
 */

#ifndef ACSL_VOCABULARY_H
#define ACSL_VOCABULARY_H

/*@
  logic integer c_strlen(char *s) =
    (s[0] == '\0') ? 0 : 1 + c_strlen(s + 1);

  predicate valid_c_string(char *s) =
    s != \null && 0 <= c_strlen(s) && \valid_read(s + (0 .. c_strlen(s)));

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
