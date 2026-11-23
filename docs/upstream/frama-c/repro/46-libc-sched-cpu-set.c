/* Frama-C libc: <sched.h> lacks cpu_set_t, CPU_* macros and
 * sched_setaffinity / sched_getaffinity (glibc _GNU_SOURCE extensions).
 *
 * Default mode is the minimal reproducer from the issue text.
 * Optional -DCHECK_macros and -DCHECK_dynamic_s cover the rest of the API.
 */
#define _GNU_SOURCE
#include <sched.h>

#if defined(CHECK_macros)
int use_fixed_macros(void)
{
  cpu_set_t a, b, c;
  CPU_ZERO(&a);
  CPU_ZERO(&b);
  CPU_ZERO(&c);
  CPU_SET(0, &a);
  CPU_SET(65, &a);
  CPU_CLR(65, &a);
  CPU_SET(0, &b);
  CPU_OR(&c, &a, &b);
  CPU_AND(&c, &a, &b);
  CPU_XOR(&c, &a, &b);
  int ok = CPU_ISSET(0, &a) && !CPU_ISSET(65, &a) && CPU_EQUAL(&a, &b);
  int cnt = CPU_COUNT(&a);
  int g = sched_getaffinity(0, sizeof(b), &b);
  int s = sched_setaffinity(0, sizeof(a), &a);
  return ok + (cnt > CPU_SETSIZE) + g + s;
}
#elif defined(CHECK_dynamic_s)
#include <stdlib.h>

int use_dynamic_s(void)
{
  size_t sz = CPU_ALLOC_SIZE(2048);
  cpu_set_t *a = malloc(sz);
  cpu_set_t *b = malloc(sz);
  cpu_set_t *c = malloc(sz);
  int r = 0;
  if (a && b && c) {
    CPU_ZERO_S(sz, a);
    CPU_ZERO_S(sz, b);
    CPU_ZERO_S(sz, c);
    CPU_SET_S(1500, sz, a);
    CPU_SET_S(1500, sz, b);
    CPU_OR_S(sz, c, a, b);
    CPU_AND_S(sz, c, a, b);
    CPU_XOR_S(sz, c, a, b);
    r = CPU_ISSET_S(1500, sz, a) + CPU_EQUAL_S(sz, a, b) + CPU_COUNT_S(sz, a);
    CPU_CLR_S(1500, sz, a);
    r += sched_setaffinity(0, sz, a) + sched_getaffinity(0, sz, b);
  }
  free(c);
  free(b);
  free(a);
  return r;
}
#else
int pin_to_cpu0(void)
{
  cpu_set_t mask;
  CPU_ZERO(&mask);
  CPU_SET(0, &mask);
  return sched_setaffinity(0, sizeof(mask), &mask);
}
#endif
