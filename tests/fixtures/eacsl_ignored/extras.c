/* One construct per build (-DX_<NAME>), so that a hard failure of one hides nothing else
 * (tests/test_eacsl_ignored_annotations.py, scenario.sh). Line numbers are in the captured logs. */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

struct pair {
  int a;
  int b;
};

#ifdef X_AT
/*@ requires n >= 1 && \valid(t + (0 .. n - 1));
    assigns t[0 .. n - 1];
    ensures shifted: \forall integer i; 0 <= i < n - 1 ==> \old(t[i]) == t[i + 1];
*/
void probe_fn(int *t, int n)
{
  for (int i = n - 1; i > 0; i--)
    t[i] = t[i - 1];
}
#define CALL { int t[4] = {1, 1, 1, 1}; probe_fn(t, 4); }
#endif

#ifdef X_STRUCT
/*@ requires \valid_read(p) && \valid_read(q);
    assigns \nothing;
    ensures same: \result == 1 ==> *p == *q;
*/
int probe_fn(const struct pair *p, const struct pair *q)
{
  return p->a == q->a && p->b == q->b;
}
#define CALL { struct pair x = {1, 2}; probe_fn(&x, &x); }
#endif

#ifdef X_DECREASES
/*@ requires 0 <= n <= 8;
    decreases n;
    assigns \nothing;
    ensures \result >= 0;
*/
int probe_fn(int n)
{
  return n == 0 ? 0 : 1 + probe_fn(n - 1);
}
#define CALL { probe_fn(3); }
#endif

#ifdef X_TERMINATES
/*@ requires 0 <= n <= 8;
    terminates n >= 0;
    assigns \nothing;
    ensures \result == n;
*/
int probe_fn(int n)
{
  return n;
}
#define CALL { probe_fn(3); }
#endif

#ifdef X_EXISTS
/*@ requires 0 <= n <= 8;
    assigns \nothing;
    ensures witness: \exists integer k; k >= 0 && k == \result;
*/
int probe_fn(int n)
{
  return n;
}
#define CALL { probe_fn(3); }
#endif

#ifdef X_FRESH
/*@ requires 0 < n <= 8;
    allocates \result;
    ensures fresh: \result != \null ==> \fresh(\result, n);
*/
char *probe_fn(size_t n)
{
  return malloc(n);
}
#define CALL { free(probe_fn(3)); }
#endif

#ifdef X_AXIOMATIC
/*@ axiomatic Sum {
      logic integer sum(int *a, integer n) reads a[0 .. n - 1];
      axiom sum_empty: \forall int *a; sum(a, 0) == 0;
    }
*/
/*@ requires 0 <= n <= 4 && \valid_read(a + (0 .. n - 1));
    assigns \nothing;
    ensures total: \result == sum(a, n);
*/
int probe_fn(const int *a, int n)
{
  int s = 0;
  for (int i = 0; i < n; i++)
    s += a[i];
  return s;
}
#define CALL { int t[1] = {0}; probe_fn(t, 0); }
#endif

#ifdef X_WITH
/*@ requires \valid(p);
    assigns *p;
    ensures updated: *p == { \old(*p) \with .a = (int)0 };
*/
void probe_fn(struct pair *p)
{
  p->a = 0;
}
#define CALL { struct pair x = {1, 2}; probe_fn(&x); }
#endif

#ifdef X_BEHAVIOR
/*@ requires 0 <= n <= 8;
    assigns \nothing;
    behavior zero:
      assumes n == 0;
      ensures unb_beh: \forall integer k; 0 <= k ==> k + \result >= 0;
    behavior other:
      assumes n != 0;
      ensures \result == n;
    complete behaviors;
    disjoint behaviors;
*/
int probe_fn(int n)
{
  return n;
}
#define CALL { probe_fn(3); probe_fn(0); }
#endif

#ifdef X_EXITS
/*@ requires 0 <= n <= 8;
    exits never: \false;
    assigns \nothing;
    ensures \result == n;
*/
int probe_fn(int n)
{
  return n;
}
#define CALL { probe_fn(3); }
#endif

#ifdef X_ALLOCATES
/*@ requires \valid(p);
    frees p;
    allocates \nothing;
    assigns \nothing;
*/
void probe_fn(char *p)
{
  free(p);
}
#define CALL { probe_fn(malloc(4)); }
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  (void)data;
  (void)size;
  CALL
  return 0;
}
