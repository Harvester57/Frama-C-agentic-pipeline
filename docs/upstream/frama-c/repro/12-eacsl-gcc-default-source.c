#include <string.h>
#include <stdlib.h>

int main(void) {
  char *d = strdup("abc"); /* POSIX: declared only with _DEFAULT_SOURCE & co */
  int ok = d != 0 && d[0] == 'a';
  free(d);
  return !ok;
}
