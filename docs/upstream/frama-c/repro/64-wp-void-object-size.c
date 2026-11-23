#ifdef CASE_mempcpy
#define _GNU_SOURCE
#include <string.h>

/*@ requires \valid(d + (0 .. 7)) && \valid_read(s + (0 .. 1));
    requires \separated(d + (0 .. 7), s + (0 .. 1)); */
void call_mempcpy(char *d, const char *s) {
  void *r = mempcpy(d, s, 2);
  //@ assert wrong: (char *)r == d + 8;
}
#else
char buf[8];

void bl_true(void) {
  void *p = buf;
  //@ check bl_8: \block_length(p) == 8;
}

void bl_false(void) {
  void *p = buf;
  //@ check bl_32: \block_length(p) == 32;
}

void shift_true(void) {
  void *p = buf;
  //@ check sh_4: (char *)(p + 4) == buf + 4;
}

void shift_false(void) {
  void *p = buf;
  //@ check sh_16: (char *)(p + 4) == buf + 16;
}

void diff_true(void) {
  void *p = buf;
  void *q = buf + 4;
  //@ check diff_4: q - p == 4;
}

void diff_false(void) {
  void *p = buf;
  void *q = buf + 4;
  //@ check diff_1: q - p == 1;
}
#endif
