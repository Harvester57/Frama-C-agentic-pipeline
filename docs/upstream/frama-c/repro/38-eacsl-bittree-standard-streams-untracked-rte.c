#include <stdio.h>

int main(int argc, char **argv) {
  fputs("to stdout\n", stdout);
  fprintf(stderr, "to stderr %d\n", argc);
  return 0;
}
