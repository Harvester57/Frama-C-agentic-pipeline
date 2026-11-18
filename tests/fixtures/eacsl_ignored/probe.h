#ifndef PROBE_H
#define PROBE_H
#include <stddef.h>

/* Never used by a contract: E-ACSL translates a logic definition only where it is used. */
/*@ predicate hdr_unused_unbounded(integer n) = \forall integer i; 0 <= i ==> i + n >= 0; */

/*@ predicate hdr_tail_nonneg(integer n) = \forall integer i; 0 <= i ==> i + n >= 0; */

/*@ requires n <= 16;
    requires hdr_unb: \forall integer i; 0 <= i ==> i + n >= 0;
    assigns \nothing;
    ensures \result == n + 1;
*/
int hdr_fn(size_t n);

#endif
