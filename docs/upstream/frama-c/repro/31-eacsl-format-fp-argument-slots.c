#include <stdio.h>

int main(void) {
  char t[64];
  const char *s = "abc";
  snprintf(t, sizeof t, "%f %s", 1.5, s);
  return puts(t) < 0;
}
