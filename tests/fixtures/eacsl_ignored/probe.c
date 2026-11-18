/* Probe for the annotations E-ACSL ignores (tests/test_eacsl_ignored_annotations.py, scenario.sh).
 * The line numbers of this file are in the captured logs: do not edit it without capturing again. */
#include <stddef.h>
#include <stdint.h>
#include "probe.h"

/*@ predicate tail_nonneg(integer n) = \forall integer i; 0 <= i ==> i + n >= 0; */

/*@ predicate wraps_tail(integer n) = n >= 0 && tail_nonneg(n); */

/*@ requires n <= 16;
    requires readable: n > 0 ==> \valid_read(buf + (0 .. n - 1));
    requires unb_pre: \forall integer i; 0 <= i ==> i + n >= 0;
    assigns \nothing;
    ensures small: \result <= 16;
*/
unsigned unb_requires(const unsigned char *buf, size_t n)
{
  unsigned z = 0;
  /*@ loop invariant 0 <= i <= n;
      loop invariant z <= i;
      loop assigns i, z;
      loop variant n - i;
  */
  for (size_t i = 0; i < n; i++)
    if (buf[i] == 0)
      z++;
  return z;
}

/*@ requires n <= 16;
    assigns \nothing;
    ensures unb_post: \forall integer k; 0 <= k ==> \result + k >= 0;
    ensures bounded_post: \forall integer k; 0 <= k < 4 ==> \result + k >= 0;
*/
int unb_ensures(size_t n)
{
  return (int)n;
}

/*@ requires valid_read_string(s);
    assigns \nothing;
    ensures \result <= 16;
*/
size_t walk(const char *s)
{
  size_t n = 0;
  /*@ loop invariant n <= 16;
      loop assigns s, n;
      loop variant strlen(s) + 0;
  */
  while (*s) {
    s++;
    n++;
  }
  return n;
}

/*@ requires 0 <= n <= 16;
    requires n > 0 ==> \valid_read(buf + (0 .. n - 1));
    assigns \nothing;
    ensures \result <= 255 * 16;
*/
unsigned plain(const unsigned char *buf, int n)
{
  unsigned s = 0;
  /*@ loop invariant 0 <= i <= n;
      loop invariant s <= 255 * i;
      loop assigns i, s;
      loop variant n - i;
  */
  for (int i = 0; i < n; i++)
    s += buf[i];
  return s;
}

/*@ requires n <= 16;
    requires via: tail_nonneg(n);
    assigns \nothing;
    ensures \result == (int)n;
*/
int via_pred(size_t n)
{
  return (int)n;
}

/*@ requires n <= 16;
    requires wrapped: wraps_tail(n);
    assigns \nothing;
    ensures \result == (int)n;
*/
int via_wrapped(size_t n)
{
  return (int)n;
}

/*@ requires n <= 16;
    requires from_hdr: hdr_tail_nonneg(n);
    assigns \nothing;
    ensures \result == (int)n;
*/
int via_hdr_pred(size_t n)
{
  return (int)n;
}

int hdr_fn(size_t n)
{
  return (int)n + 1;
}

int body_assert(size_t n)
{
  int r = (int)n;
  /*@ assert unb_assert: \forall integer i; 0 <= i ==> i + r >= 0; */
  return r;
}

/*@ requires 0 <= n <= 16;
    requires split:
      \forall integer i;
        0 <= i ==> i + n >= 0;
    assigns \nothing;
    ensures \result == n;
*/
int multi_line(int n)
{
  int s = 0;
  /*@ loop invariant 0 <= i <= n;
      loop invariant unb_inv:
        \forall integer k; 0 <= k ==> k + s >= 0;
      loop invariant s == i;
      loop assigns i, s;
      loop variant n - i;
  */
  for (int i = 0; i < n; i++)
    s++;
  return s;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  unsigned char bytes[16] = {0};
  char text[17] = {0};
  size_t n = size > 16 ? 16 : size;
  for (size_t i = 0; i < n; i++) {
    bytes[i] = data[i];
    text[i] = (char)data[i];
  }
  unb_requires(bytes, n);
  unb_ensures(n);
  walk(text);
  plain(bytes, (int)n);
  via_pred(n);
  via_wrapped(n);
  via_hdr_pred(n);
  hdr_fn(n);
  body_assert(n);
  multi_line((int)n);
  return 0;
}
