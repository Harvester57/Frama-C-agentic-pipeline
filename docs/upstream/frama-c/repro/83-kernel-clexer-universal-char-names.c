#include <stddef.h>
#ifdef CASE_valid
const wchar_t *ws1 = L"\u20AC";
const wchar_t *ws2 = L"\U0001F600";
wchar_t wc = L'\u20AC';
const char *s = "\u20AC";
void main(void) {
  /*@ check ws1[0] == 0x20AC && ws1[1] == 0; */
  /*@ check ws2[0] == 0x1F600 && ws2[1] == 0; */
  /*@ check wc == 0x20AC; */
  /*@ check (unsigned char)s[0] == 0xE2 && (unsigned char)s[1] == 0x82 && (unsigned char)s[2] == 0xAC && s[3] == 0; */
}
#elif defined(CASE_surrogate)
wchar_t bad = L'\uD800';
#elif defined(CASE_low)
wchar_t bad = L'\u0041';
#elif defined(CASE_high)
wchar_t bad = L'\U00110000';
#endif
