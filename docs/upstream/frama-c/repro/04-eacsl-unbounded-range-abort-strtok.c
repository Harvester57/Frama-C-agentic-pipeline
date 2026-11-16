#include <string.h>

int main(void) {
  char buf[] = "a:b";
  char *save = 0;
  char *tok = strtok_r(buf, ":", &save);
  return tok == 0;
}
