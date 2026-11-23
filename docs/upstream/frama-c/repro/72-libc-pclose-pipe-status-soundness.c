#include <stdio.h>

int close_immediately(void) {
  FILE *p = popen("ls", "r");
  if (p == NULL)
    return -1;
  pclose(p);
  //@ assert unreachable_false: \false;
  return 0;
}

int read_then_close(void) {
  FILE *p = popen("ls", "r");
  if (p == NULL)
    return -1;
  char buf[16];
  fread(buf, 1, sizeof(buf), p);
  pclose(p);
  return 0;
}
