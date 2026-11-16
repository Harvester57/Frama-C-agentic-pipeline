#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
  unsigned char uc = 200;
  unsigned short us = 60000;
  signed char sc = -1;
  switch (argc > 1 ? atoi(argv[1]) : 0) {
  case 0: return printf("%x\n", uc) < 0;        /* unsigned char */
  case 1: return printf("%u\n", us) < 0;        /* unsigned short */
  case 2: return printf("%hhu\n", uc) < 0;      /* accepted before too */
  case 3: return printf("%u\n", sc) < 0;        /* negative signed char */
  case 4: return printf("%u\n", 7) < 0;         /* int */
  case 5: return printf("%d\n", 7u) < 0;        /* unsigned int */
  }
  return 1;
}
