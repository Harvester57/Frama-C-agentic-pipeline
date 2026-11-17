#include <stdlib.h>
#include <string.h>

/* Allocates 2 MB on the heap and writes every byte. */
int main(int argc, char **argv) {
  size_t n = 2 * 1024 * 1024;
  char *p = malloc(n);
  if (!p)
    return 2;
  memset(p, 1, n);
  int r = p[n - 1] - 1;
  free(p);
  return r;
}
