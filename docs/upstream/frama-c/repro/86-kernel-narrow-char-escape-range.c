#ifdef CASE_oct
int c = '\777';
#elif defined(CASE_hex)
int c = '\x1ff';
#elif defined(CASE_multi)
int c = 'a\x100';
#elif defined(CASE_valid)
#include <stddef.h>
int c1 = '\377';
int c2 = '\xff';
int c3 = 'ab';
wchar_t w1 = L'\777';
wchar_t w2 = L'\x1ff';
#endif
