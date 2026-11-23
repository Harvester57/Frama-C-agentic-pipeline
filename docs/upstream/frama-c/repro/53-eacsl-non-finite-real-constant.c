int main(void) {
  double x = 0.5;
#ifdef CASE_float_ovf
  /*@ assert x < 1e40f; */
#endif
#ifdef CASE_double_ovf
  /*@ assert x < 1e400d; */
#endif
#ifdef CASE_hex_ovf
  /*@ assert x < 0x1p2000d; */
#endif
#ifdef CASE_gmp_ovf
  /*@ assert 0.1 < 1e40f; */
#endif
#ifdef CASE_float_ovf_hexprint
  /*@ assert x < 1e40f; */
#endif
  /*@ assert x == 0.5; */
  return 0;
}
