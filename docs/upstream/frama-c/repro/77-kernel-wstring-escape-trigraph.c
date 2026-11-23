#ifdef CASE_run
#include <stddef.h>
#include <stdio.h>
wchar_t a[] = L"\x20AC";
wchar_t b[] = L"\x1F600";
wchar_t c[] = L"\x1F600""A";
wchar_t e[] = L"\x110000";
wchar_t t[] = L"a?\?!b";
int main(void) {
  printf("a=%x b=%x/%zu c=%x,%x/%zu e=%x t=%zu:%x,%x,%x,%x,%x\n",
         (unsigned)a[0], (unsigned)b[0], sizeof(b),
         (unsigned)c[0], (unsigned)c[1], sizeof(c),
         (unsigned)e[0], sizeof(t) / sizeof(t[0]),
         (unsigned)t[0], (unsigned)t[1], (unsigned)t[2],
         (unsigned)t[3], (unsigned)t[4]);
  return 0;
}
#endif

#ifdef CASE_surrogate
#include <stddef.h>
#include <stdio.h>
wchar_t d[] = L"\xD800";
int main(void) {
  printf("d=%x/%zu\n", (unsigned)d[0], sizeof(d));
  return 0;
}
#endif

#ifdef CASE_reparse
#include <stddef.h>
wchar_t a[] = L"\x20AC";
wchar_t b[] = L"\x1F600";
wchar_t c[] = L"\x1F600""A";
wchar_t d[] = L"\xD800";
wchar_t e[] = L"\x110000";
wchar_t t[] = L"a?\?!b";
#endif

#ifdef CASE_huge
#include <stddef.h>
wchar_t huge[] = L"\x100000000";
#endif
