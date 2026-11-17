#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
  char u[3] = {'x', 'y', 'z'}; /* not NUL-terminated */
  const char *s = "abc";
  long lw = 5;
  switch (argc > 1 ? atoi(argv[1]) : 0) {
  case 0: return printf("[%*d]\n", 5, 42) < 0;
  case 1: return printf("[%-*.*f]\n", 10, 2, 3.14159) < 0;
  case 2: return printf("[%*s|%s]\n", 4, s, s) < 0;
  case 3: return printf("[%.*s]\n", 3, u) < 0;
  case 4: return printf("[%s %05d]\n", s, 5) < 0;
  /* must abort: a long for '*' */
  case 5: return printf("[%*d]\n", lw, 42) < 0;
  /* must abort: precision larger than u */
  case 6: return printf("[%.*s]\n", 4, u) < 0;
  /* must abort: u is unterminated, on directive 2 */
  case 7: return printf("[%*d %s]\n", 3, 1, u) < 0;
  /* numbered '*' (POSIX), not supported */
  case 8: return printf("[%2$*1$d]\n", 5, 42) < 0;
  }
  return 0;
}
