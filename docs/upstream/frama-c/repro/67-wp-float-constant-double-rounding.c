/*@ check lemma dr_above_mid_bad:
      (float)1.0000000596046447753906250000000000000001 == 1.0;
    check lemma dr_above_mid_ok:
      (float)1.0000000596046447753906250000000000000001
      == 1.00000011920928955078125;
    check lemma dr_fltmax_ok:
      (float)340282356779733661637539395458142568447.0
      == 340282346638528859811704183484516925440.0;
    check lemma dr_subnormal_ok:
      (float)(1.0 / 1427247692705959881058285969449495136382746624.0 + 1e-65)
      == (1.0 / 713623846352979940529142984724747568191373312.0); */

/* x = 2^60 + 2^36 + 1; nearest float is 2^60 + 2^37 = 1152921642045800448 */
/*@ ensures to_float_bad: \result == 1152921504606846976.0; */
float to_float_wrong(void) {
  long long x = 1152921573326323713LL;
  return (float)x;
}

/*@ ensures to_float_ok: \result == 1152921642045800448.0; */
float to_float_right(void) {
  long long x = 1152921573326323713LL;
  return (float)x;
}
