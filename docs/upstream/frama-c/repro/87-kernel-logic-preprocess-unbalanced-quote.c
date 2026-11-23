#ifdef CASE_unbalanced_str
void f(void) {
  //@ check o5: "abc == 1;
}
#elif defined(CASE_c23_sep)
void f(void) {
  //@ check c23: 1'000 == 1000;
}
#elif defined(CASE_unbalanced_char)
void f(void) {
  //@ check ch: 'a == 1;
}
#endif
