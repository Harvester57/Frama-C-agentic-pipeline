/* A contract that is false on every input longer than zero, beside a clause E-ACSL ignores
 * (tests/test_eacsl_ignored_annotations.py, scenario.sh). Line numbers are in the captured files. */
#include <stddef.h>
#include <stdint.h>

/*@ requires n <= 16;
    requires unb_pre: \forall integer i; 0 <= i ==> i + n >= 0;
    assigns \nothing;
    ensures wrong: \result == 0;
*/
int wrong_post(size_t n)
{
  return (int)n;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  (void)data;
  wrong_post(size > 16 ? 16 : size);
  return 0;
}
