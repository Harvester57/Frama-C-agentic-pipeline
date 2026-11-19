/* Issue 42: WP and the floating-point literals it does not read.
   One case per run, selected with -cpp-extra-args=-DCASE_<name>: a lemma that
   WP rejects stops the whole run. */

#ifdef CASE_contract
/* The bound is DBL_MAX from Frama-C's <float.h>: 0x1.fffffffffffffp+1023.
   The postcondition repeats the precondition, so Qed alone proves it. */
#include <float.h>
/*@ requires x <= DBL_MAX;
    ensures x <= DBL_MAX;
*/
void contract(double x) { (void)x; }
#endif

#ifdef CASE_lemma
/*@ lemma hexa: 0x1.8p1 == 3.0; */
#endif

#ifdef CASE_suffix
/*@ lemma f32: 1.5f32 == 1.5; */
#endif

#ifdef CASE_real
/* Both are false: 0x1.8p1 is 3. Run with -wp-model +real. */
/*@ lemma three_is_zero: 0x1.8p1f == 0.0; */
/*@ ensures \result == 0.0; */
float three(void) { return 0x1.8p1f; }
#endif
