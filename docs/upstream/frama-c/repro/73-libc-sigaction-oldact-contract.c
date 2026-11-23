#include <signal.h>

void h1(int s) { (void)s; }
void h2(int s) { (void)s; }

int two_call(void) {
  struct sigaction a = {0}, b = {0}, old = {0};
  a.sa_handler = h1;
  b.sa_handler = h2;
  sigaction(SIGINT, &a, 0);
  sigaction(SIGINT, &b, &old);
  //@ assert old_is_h1: old.sa_handler == h1;
  return 0;
}

int single_call(void) {
  struct sigaction b = {0}, old = {0};
  b.sa_handler = h1;
  sigaction(SIGINT, &b, &old);
  //@ assert reached: \true;
  return 0;
}

int query_after_install(void) {
  struct sigaction a = {0}, old = {0};
  a.sa_handler = h1;
  sigaction(SIGINT, &a, 0);
  sigaction(SIGINT, 0, &old);
  //@ assert queried_h1: old.sa_handler == h1;
  return 0;
}
