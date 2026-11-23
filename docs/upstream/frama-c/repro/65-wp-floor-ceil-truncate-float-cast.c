/*@ check lemma floor_near_ok:    \floor(0.99999999999999999999) == 0;
    check lemma floor_near_bad:   \floor(0.99999999999999999999) == 1;
    check lemma ceil_near_ok:     \ceil(0.99999999999999999999) == 1;
    check lemma ceil_near_bad:    \ceil(0.99999999999999999999) == 2;
    check lemma trunc_near_ok:    \truncate(-0.99999999999999999999) == 0;
    check lemma trunc_near_bad:   \truncate(-0.99999999999999999999) == -1;
    check lemma floor_big_ok:     \floor(9007199254740993.5) == 9007199254740993;
    check lemma floor_big_bad:    \floor(9007199254740993.5) == 9007199254740994;
    check lemma cast_int_ok:      (integer)0.99999999999999999999 == 0;
    check lemma cast_int_bad:     (integer)0.99999999999999999999 == 1;
    check lemma floor_huge_ok:    \floor(1e30) == 1000000000000000000000000000000;
    check lemma floor_huge_bad:   \floor(1e30) == 0; */

/*@ ensures ok_ll: \result == 5000000000000000000; */
long long trunc_ll_ok(void) {
  double d = 5e18;
  return (long long)d;
}

/*@ ensures bad_ll: \result == -4223372036854775808; */
long long trunc_ll_bad(void) {
  double d = 5e18;
  return (long long)d;
}

/*@ ensures ok_ull: \result == 4611686018427387904ULL; */
unsigned long long trunc_ull_ok(void) {
  float f = 4611686018427387904.0f;
  return (unsigned long long)f;
}

/*@ ensures bad_ull: \result == 13835058055282163712ULL; */
unsigned long long trunc_ull_bad(void) {
  float f = 4611686018427387904.0f;
  return (unsigned long long)f;
}
