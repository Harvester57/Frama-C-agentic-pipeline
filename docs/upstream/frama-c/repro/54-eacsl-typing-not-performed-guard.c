#ifdef CASE_quant
/*@ logic integer undef_fn(int x); */
int main(void) {
  int x = 0;
  /*@ assert \forall integer i; undef_fn(x) <= i < 3 ==> i >= 0; */
  return 0;
}
#endif

#ifdef CASE_binop_reads
/*@ logic integer f(char *p) reads *p; */
/*@ ensures \result == f(a) + f(b); */
int g(char *a, char *b);
int main(void) {
  char x = 0;
  g(&x, &x);
  return 0;
}
#endif

#ifdef CASE_stpncpy
#include <string.h>
int main(void) {
  char d[4];
  stpncpy(d, "ab", 4);
  return 0;
}
#endif

#ifdef CASE_strlcat
#include <string.h>
int main(void) {
  char d[8] = "a";
  strlcat(d, "ab", 8);
  return 0;
}
#endif
