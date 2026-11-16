#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
  char t[64];
  const char *s = "abc";
  char u[3] = {'x', 'y', 'z'}; /* not NUL-terminated */
  int n;
  int r = -1;
  switch (argc > 1 ? atoi(argv[1]) : 0) {
  case 0: r = snprintf(t, sizeof t, "%Lf %s", 2.5L, s); break;
  case 1: r = snprintf(t, sizeof t, "%f%n", 1.5, &n); break;
  case 2: r = snprintf(t, sizeof t, "%s", u); break;          /* no double */
  case 3: r = snprintf(t, sizeof t, "%f %s %s", 1.5, u, s); break;
  case 4: r = snprintf(t, sizeof t, "%f %s", 1.5, u, s); break; /* extra arg */
  }
  return r < 0;
}
