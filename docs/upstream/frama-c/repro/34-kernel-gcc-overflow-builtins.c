/* GCC's type-generic overflow builtins compute the result in infinite
   precision, store it converted to the type of *res, and return whether it
   fits. Operands and result may have any integer types. CASE selects one
   call; the program returns the flag. */
#include <limits.h>

int test(void)
{
#if CASE == 1 /* int operands, long result: 2^32 fits in long */
  int a = 65536, b = 65536; long r;
  return __builtin_mul_overflow(a, b, &r);       /* gcc: 0 */
#elif CASE == 2 /* first operand int, second long: 1 + 0x17fffffff fits */
  int a = 1; long b = 0x17fffffffL, r;
  return __builtin_add_overflow(a, b, &r);       /* gcc: 0 */
#elif CASE == 3 /* int operands, unsigned result: -1 does not fit */
  int a = -1, b = 0; unsigned r;
  return __builtin_add_overflow(a, b, &r);       /* gcc: 1 */
#elif CASE == 4 /* unsigned char operands and result */
  unsigned char a = 200, b = 100, r;
  return __builtin_add_overflow(a, b, &r);       /* gcc: 1 */
#elif CASE == 5 /* the _p form: only the type of the third argument counts */
  int a = INT_MAX;
  return __builtin_add_overflow_p(a, 1, (int)0); /* gcc: 1 */
#endif
}

int main(void)
{
  int o = test();
#ifdef __FRAMAC__
  Frama_C_show_each_overflow(o);
#endif
  return o;
}
