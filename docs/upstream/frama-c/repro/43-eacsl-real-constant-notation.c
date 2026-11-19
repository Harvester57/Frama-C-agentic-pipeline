/* Issue 43: real constants that are not exactly a double, one case per build
   (-DCASE_<name>). See 43-eacsl-real-constant-notation.sh. */
int main(void) {
  double x = 0.5;
#ifdef CASE_exponent
  /*@ assert 1e-1 == 0.1; */ /* true */
#endif
#ifdef CASE_tolerance
  /*@ assert x - 0.5 <= 1e-9; */ /* true */
#endif
#ifdef CASE_exponent_false
  /*@ assert 1e-1 != 0.1; */ /* false: the program must abort */
#endif
#ifdef CASE_hexadecimal
  /*@ assert 0x1.00000000000000001p0 > 1; */ /* true */
#endif
#ifdef CASE_long_double
  /*@ assert 0.1L > 0.05; */ /* true */
#endif
#ifdef CASE_long_double_false
  /*@ assert 0.1L == 0; */ /* false */
#endif
  return (int)x;
}
