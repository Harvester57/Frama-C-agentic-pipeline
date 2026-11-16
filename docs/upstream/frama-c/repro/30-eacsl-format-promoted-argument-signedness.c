#include <stdio.h>

int main(void) {
  const unsigned char a[4] = {192, 168, 1, 200};
  char t[16];
  snprintf(t, sizeof t, "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
  return puts(t) < 0;
}
