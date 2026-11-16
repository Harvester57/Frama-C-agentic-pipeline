#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
  const char *v = getenv("EACSL_REPRO_VAR");
  printf("argc=%d EACSL_REPRO_VAR=%s\n", argc, v ? v : "(null)");
  return v ? 0 : 1;
}
