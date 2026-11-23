#include <stddef.h>

#ifdef CASE_esc
int main(void) {
  //@ check s1: sizeof(L"\n\t") == 3 * sizeof(wchar_t);
  //@ check s2: sizeof(L"a\"b") == 4 * sizeof(wchar_t);
  //@ check s3: sizeof(L"a\\b") == 4 * sizeof(wchar_t);
  //@ check s4: sizeof(L"\351") == 2 * sizeof(wchar_t);
  //@ check s5: sizeof(L"a'b") == 4 * sizeof(wchar_t);
  return 0;
}
#endif

#ifdef CASE_empty
int main(void) {
  //@ check e1: sizeof(L"") == 1 * sizeof(wchar_t);
  return 0;
}
#endif
