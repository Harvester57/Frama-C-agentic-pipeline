#include <stdio.h>
#include <stdlib.h>

static void show(const char *p) {
  printf("[%s]\n", p);
}

int main(int argc, char **argv) {
  char b[8] = "hey";
  char u[3] = {'x', 'y', 'z'}; /* not NUL-terminated */
  const char *p = b;
  int n = 0;
  switch (argc > 1 ? atoi(argv[1]) : 0) {
  case 0: return printf("%s\n", b) < 0;
  case 1: return printf("%s\n", p) < 0;
  case 2: show(b); return 0;
  case 3: printf("%s%n\n", "ab", &n); return printf("n=%d\n", n) < 0;
  /* the example of the user manual: must abort on the type */
  case 4: return printf("is %d really an int?", "foo") < 0;
  /* must abort: u is unterminated */
  case 5: return printf("%s\n", u) < 0;
  case 6: show(u); return 0;
  }
  return 0;
}
