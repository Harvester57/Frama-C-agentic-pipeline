/* Frama-C libc: <sched.h> has no cpu_set_t, no CPU_* macros and no
 * sched_setaffinity / sched_getaffinity, even under _GNU_SOURCE.
 *
 *   frama-c -machdep gcc_x86_64 46-libc-sched-cpu-set.c
 *     -> User Error: syntax error (before or at token: mask)
 *   gcc -fsyntax-only -Wall 46-libc-sched-cpu-set.c
 *     -> accepted
 */
#define _GNU_SOURCE
#include <sched.h>

int pin_to_cpu0(void)
{
  cpu_set_t mask;
  CPU_ZERO(&mask);
  CPU_SET(0, &mask);
  return sched_setaffinity(0, sizeof(mask), &mask);
}
