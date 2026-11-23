#ifdef CASE_double_true
int main(void) {
  double d = 0.1;
  /*@ assert d == (double)0.1; */
  return 0;
}
#endif

#ifdef CASE_double_false_eq
int main(void) {
  double d_below = 0x1.9999999999999p-4;
  /*@ assert d_below == (double)0.1; */
  return 0;
}
#endif

#ifdef CASE_double_false_lt
int main(void) {
  /*@ assert (double)0.1 < 0.1; */
  return 0;
}
#endif

#ifdef CASE_double_neg
int main(void) {
  double nd = -0.1;
  /*@ assert nd == (double)(0 - 0.1); */
  return 0;
}
#endif

#ifdef CASE_double_tie
int main(void) {
  double one = 1.0;
  double half_ulp = 0x1p-53;
  double u2 = 0x1.0000000000002p0;
  /*@ assert one == (double)(1 + half_ulp); */
  /*@ assert u2 == (double)(1 + 3 * half_ulp); */
  return 0;
}
#endif

#ifdef CASE_float_dr
int main(void) {
  float f = 16777218.0f;
  /*@ assert f == (float)16777217.0000000001; */
  return 0;
}
#endif

#ifdef CASE_subnormal
int main(void) {
  double ds = 0x1p-1074;
  float fs = 0x1p-149f;
  /*@ assert ds == (double)(3 * ds / 4); */
  /*@ assert fs == (float)(3 * fs / 4); */
  return 0;
}
#endif
