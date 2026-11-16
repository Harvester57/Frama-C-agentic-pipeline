#include <string.h>

int main(void) {
  char buf[8] = "abababa";
  int same = memcmp(buf, buf, 4);        /* identical ranges */
  int overlap = memcmp(buf, buf + 2, 4); /* overlapping ranges */
  return (same == 0 && overlap == 0) ? 0 : 1;
}
