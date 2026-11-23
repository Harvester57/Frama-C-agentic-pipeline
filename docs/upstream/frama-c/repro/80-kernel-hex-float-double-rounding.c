void main(void) {
  float f_up = 0x1.0000010000000001p0f;
  float f_neg = -0x1.0000010000000001p0f;
  float f_sub = 0x1.0000000000000001p-150f;
  float f_tie_even = 0x1.000001p0f;
  float f_tie_odd = 0x1.000003p0f;
  /*@ check f_up == 0x1.000002p0f; */
  /*@ check f_neg == -0x1.000002p0f; */
  /*@ check f_sub == 0x1p-149f; */
  /*@ check f_tie_even == 0x1.000000p0f; */
  /*@ check f_tie_odd == 0x1.000004p0f; */
}
