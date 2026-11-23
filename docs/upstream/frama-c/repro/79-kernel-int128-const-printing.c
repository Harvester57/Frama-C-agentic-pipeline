#include <stdio.h>

int main(void) {
  __int128 v = ((__int128)1 << 100) + 5;
  unsigned __int128 u = ~(unsigned __int128)0;
  __int128 m = -((__int128)1 << 126) - ((__int128)1 << 126);
  __int128 neg = -((__int128)1 << 100) - 5;
  __int128 small = 42;
  printf("%llx %llx | %llx %llx | %llx %llx | %llx %llx | %llx %llx\n",
         (unsigned long long)((unsigned __int128)v >> 64), (unsigned long long)v,
         (unsigned long long)(u >> 64), (unsigned long long)u,
         (unsigned long long)((unsigned __int128)m >> 64), (unsigned long long)m,
         (unsigned long long)((unsigned __int128)neg >> 64), (unsigned long long)neg,
         (unsigned long long)((unsigned __int128)small >> 64), (unsigned long long)small);
  return 0;
}
