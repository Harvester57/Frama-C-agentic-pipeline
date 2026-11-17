#include <stdio.h>

int main(void) {
  char buf[8] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'}; /* no NUL */
  int n = 8;
  return printf("RECORD:%.*s\n", n, buf) < 0;
}
