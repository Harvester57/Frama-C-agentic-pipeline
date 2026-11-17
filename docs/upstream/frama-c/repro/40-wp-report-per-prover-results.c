/* Three goals for -wp-prover alt-ergo,z3,cvc5:
   - fast_false is false (x = 0 is a counter-example): no prover can prove
     it, and they give up in different ways (Timeout or Unknown);
   - bounded is true and easy: the JSON "time" of a proved goal;
   - fermat3 is true but too hard (Fermat's last theorem for n = 3). */

/*@ requires 0 <= x <= 100;
    ensures fast_false: \result > 50;
*/
int fast_unknown(int x)
{
  return x;
}

/*@ requires 0 <= x <= 100 && 0 <= y <= 100;
    ensures bounded: \result <= 10000;
*/
int product(int x, int y)
{
  return x * y;
}

/*@ requires 0 < a && 0 < b && 0 < c; */
void hard_true(int a, int b, int c)
{
  /*@ assert fermat3: a * a * a + b * b * b != c * c * c; */
}
