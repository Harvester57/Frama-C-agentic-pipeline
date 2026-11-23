#include <float.h>
#include <math.h>
#include "__fc_builtin.h"

#ifdef CASE_dbl_max_alarm
int t[2];
int main(void) {
  double x = Frama_C_double_interval(1e305, 1e306);
  double m = DBL_MAX;
  int i = 0;
  if (x < m)
    i = 2;
  t[i] = 1;
  return i;
}
#endif

#ifdef CASE_hex_val
int main(void) {
  double x = Frama_C_double_interval(1.0, 2.0);
  double h = x * 0x1.8p1;
  Frama_C_domain_show_each_hex(h);
  return 0;
}
#endif

#ifdef CASE_hex_e
int main(void) {
  double z = 0x1.ep0;
  Frama_C_domain_show_each_he(z);
  return 0;
}
#endif

#ifdef CASE_flt_max
int main(void) {
  float f = FLT_MAX;
  return f > 0.0f;
}
#endif

#ifdef CASE_suffix_d
int main(void) {
  double x = 1.5d;
  Frama_C_domain_show_each_ds(x);
  return 0;
}
#endif

#ifdef CASE_infinity
int main(void) {
  float f = INFINITY;
  return f > 0.0f;
}
#endif
