#include <wchar.h>

int main(void) {
  int x = 0;
  wprintf(L"%d\n", x);
  wscanf(L"%d", &x);
  return x;
}
