#ifdef CASE_esc
void main(void) {
  int c_e = '\e';
  int c_E = '\E';
  /*@ check c_e == '\e'; */
  /*@ check c_E == '\E'; */
  /*@ check '\e' == 27 && '\E' == 27; */
}
#elif defined(CASE_unknown)
void main(void) {
  /*@ check '\z' == 0; */
}
#elif defined(CASE_unknown_str)
void main(void) {
  /*@ check sizeof("\z") == 2; */
}
#endif
