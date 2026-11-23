/*@ check lemma ovf_f32_plus1_bad: (float)1e39 + 1.0 == (float)1e39;
    check lemma ovf_f32_sub_ok:    (float)1e39 - (float)1e39 == 0.0; */

double ovf_mul(void) {
  double x = 1e308;
  double y = x * 10.0;
  double z = x * 20.0;
  //@ check plus1_bad: y + 1.0 == z;
  //@ check twice_bad: y + y == z + 5.0;
  return y;
}

float ovf_lit(void) {
  float f = 1e40f;
  //@ check lit_bad: f + 1.0 == f;
  return f;
}

void acsl_lit_inf(void) {
  //@ check acsl_bad: 1e40f + 1.0 == 1e40f;
}
