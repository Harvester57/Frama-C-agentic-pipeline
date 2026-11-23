#ifdef CASE_fold
#include <stdio.h>
static const double third = 1.0 / 3.0;
double scale(unsigned char c) { return c * (1.0 / 255.0); }
int main(void) {
  double t = 1.0 / 3.0;
  double h = 2 * 3.141592653589793;
  double g = 0.1f;
  double nz = -0.0;
  printf("%a %a %a %a %a %a\n", third, scale(255), t, h, g, nz);
  return 0;
}
#endif

#ifdef CASE_annot
int main(void) {
  float f = 0.1f;
  double d = 0x1p-68;
  double d2 = 123456789012345.0;
  /*@ assert a1: f == 0.1f; */
  /*@ assert a2: d == 0x1p-68; */
  /*@ assert a3: d2 == 123456789012345; */
  return 0;
}
#endif

#ifdef CASE_scf
extern int printf(const char *fmt, ...);
int main(void) {
  double x = 1.0 / 3.0;
  double y = 2.0 / 3.0;
  float w = 0.3f;
  printf("%a %a %a\n", x, y, (double)w);
  return 0;
}
#endif

#ifdef CASE_nonfinite
#include <stdio.h>
static double sa = 1.0 / 0.0;
static double sb = -1.0 / 0.0;
static double sc = 0.0 / 0.0;
static float sd = 1e38f * 10.0f;
static float se = 0.0f / 0.0f;
int main(void) {
  double a = 1.0 / 0.0;
  double b = -1.0 / 0.0;
  double c = 0.0 / 0.0;
  float d = 1e38f * 10.0f;
  float e = 0.0f / 0.0f;
  printf("%a %a %d %a %d | %a %a %d %a %d\n",
         a, b, c != c, (double)d, e != e,
         sa, sb, sc != sc, (double)sd, se != se);
  return 0;
}
#endif

#ifdef CASE_ext
#include <stdio.h>
int main(void) {
  _Float32 f32_inf = 1.0f32 / 0.0f32;
  _Float32 f32_nan = 0.0f32 / 0.0f32;
  _Float64 f64_inf = -1.0f64 / 0.0f64;
  _Float64 f64_val = 1.0f64 / 3.0f64;
  printf("%d %d %d %a\n", f32_inf > 0, f32_nan != f32_nan, f64_inf < 0, (double)f64_val);
  return 0;
}
#endif
