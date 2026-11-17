#include <stdio.h>

int main(void) {
  unsigned a = 192, b = 168, c = 1, d = 200;
  char t[16];
  snprintf(t, sizeof t, "%u.%u.%u.%u", a, b, c, d);
  return puts(t) < 0;
}
