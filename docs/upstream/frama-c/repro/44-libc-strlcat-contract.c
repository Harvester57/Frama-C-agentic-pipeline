/* Issue 44: five calls of strlcat that gcc with glibc defines. Each `check` states what the
 * compiled program computes (the program prints it); Eva must find each one valid. */
#include <stdio.h>
#include <string.h>

struct s {
  char d[4];
  char next;
};

#ifdef __FRAMAC__
#define expect(name, holds) ((void)0)
#else
static int failed;
static void expect(const char *name, int holds) {
  printf("%s: %s\n", name, holds ? "holds" : "DOES NOT HOLD");
  failed |= !holds;
}
#endif

int main(void) {
  /* Room for everything: the result is the length of the new string. */
  char d[8] = "ab";
  size_t r = strlcat(d, "cd", sizeof d);
  //@ check appended: r == 4;
  expect("appended", r == 4);

  /* Truncation: the result is the length of the string it tried to create. */
  char t[4] = "ab";
  size_t rt = strlcat(t, "cdef", sizeof t);
  //@ check truncated: rt == 6;
  expect("truncated", rt == 6);

  /* No NUL within the first n bytes: nothing is written, the result is n + strlen(src). */
  char f[8] = "abcdef";
  size_t rf = strlcat(f, "x", 3);
  //@ check no_nul_within_n: rf == 4;
  expect("no_nul_within_n", rf == 4);

  /* n == 0: nothing is written either. */
  size_t r0 = strlcat(f, "xy", 0);
  //@ check zero_size: r0 == 2;
  expect("zero_size", r0 == 2);

  /* The byte after the n bytes of the destination is not written. */
  struct s v = {"a", 'Z'};
  strlcat(v.d, "b", sizeof v.d);
  //@ check next_kept: v.next == 'Z';
  expect("next_kept", v.next == 'Z');

#ifndef __FRAMAC__
  return failed;
#else
  return 0;
#endif
}
