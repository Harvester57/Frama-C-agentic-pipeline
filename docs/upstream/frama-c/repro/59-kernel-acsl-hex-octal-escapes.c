#include <stddef.h>
#include <string.h>

int main(void) {
#ifdef CASE_OCT_CHAR
  //@ check bad_oct_char: '\777' == 0;
#elif defined(CASE_OCT_STR)
  //@ check bad_oct_str: strlen("\777") == 1;
#elif defined(CASE_HEX_STR)
  //@ check bad_hex_str: strlen("\x1ff") == 1;
#else
  char c = '\x041';
  wchar_t w = L'\x20AC';
  wchar_t wo = L'\777';
  wchar_t w2 = L'ab';
  //@ check c_hex: '\x041' == 'A' && c == '\x041';
  //@ check w_hex: L'\x20AC' == 0x20AC && w == L'\x20AC';
  //@ check w_oct: L'\777' == 511 && wo == L'\777';
  //@ check w_multi: w2 == L'ab';
  //@ check s_hex: strlen("\x041") == 1;
#endif
  return 0;
}
