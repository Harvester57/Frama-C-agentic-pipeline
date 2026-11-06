/* run.config*

   STDOPT: #"-eva-default-loop-unroll 10"
   STDOPT: +"-main test_split -eva-partition-value k"
   STDOPT: #"-main test_loop_split -eva-partition-history 1"
   STDOPT: #"-main test_history -eva-partition-history 0"
   STDOPT: #"-main test_history -eva-partition-history 1"
   */

#include "__fc_builtin.h"

#define N 10

volatile int nondet;

void test_unroll()
{
  int a[N], b[N], c[2*N], d[2*N], e[N], f[N], g[N];

  // The inner loop needs to be unrolled to allow strong updates
  // The outer loops doesn't need to be unrolled

  //@ loop unroll N;
  for (int i = 0; i < N; i++) {
    //@ loop unroll 1;
    for (int j = 0; j < N; j++) {
      a[i] = 42;
    }
  }

  // This time the outer loop needs unrolling but not the inner loop

  //@ loop unroll 1;
  for (int i = 0; i < N; i++) {
    //@ loop unroll N;
    for (int j = 0; j < N; j++) {
      b[j] = 42;
    }
  }

  // At the end, we must have both arrays a and b to be fully initialized at 42

  // Small loops can be unrolled without giving an unroll amount.
  // The actual limit of the number of iterations can be overridden with
  // the option -eva-default-loop-unroll
  // Here -eva-default-loop-unroll is set to a value not high enough to
  // completely unroll the loop thus a warning should be emitted.
  //@ loop unroll;
  for (int i = 0 ; i < 2*N ; i++)
    c[i] = i % 2;

  // Longer loops won't be completely unrolled when not giving a parameter
  //@ loop unroll N;
  for (int i = 0 ; i < 2*N ; i++)
    d[i] = 0;

  // Variable unroll limits can be specified as long as they evaluate as
  // a singleton in each state
  //@ loop unroll N;
  for (int i = 0 ; i < N ; i++) {
    e[i] = 1;
    //@ loop unroll i-1;
    for (int j = i - 1 ; j > 0 ; j--) {
      e[j] += e[j-1];
    }
  }

  int i = N;
  // The "continue" statements are gotos to the loop head. They should not
  // interfere with the loop unrolling: f should be entirely initialized.
  //@ loop unroll N;
  while(i > 0) {
    i--;
    f[i] = 2;
    if (nondet) continue;
    f[i] = 3;
    if (nondet) continue;
    f[i] = 4;
  }

  i = N;
  // The "break" statements are gotos to the loop head. They should not
  // interfere with the loop unrolling: g should be entirely initialized.
  //@ loop unroll N;
  while(i != 0) {
    switch (i) {
    default: i--; g[i] = 1; break;
    case 1: i=0; g[0] = 0; break;
    }
  }
}

int k;

void test_split()
{
  int i = Frama_C_interval(0,1);
  int j = Frama_C_interval(0,2);

  // The splits are done on i and j and undone in the same order
  // If global dynamic split is done on k, since it is equal to i,
  // merging i will have no effects.

  Frama_C_show_each_before_first_split(i,j,k);
  //@ split i;
  k = i;
  Frama_C_show_each_before_second_split(i,j,k);
  //@ split j;
  Frama_C_show_each_before_first_merge(i,j,k);
  //@ merge i;
  Frama_C_show_each_before_second_merge(i,j,k);
  //@ merge j;
  Frama_C_show_each_end(i,j,k);
}

void test_dynamic_split()
{
  int a, b;
  //@ dynamic_split a;
  if (nondet) {
    a = Frama_C_interval(0, 2);
    b = a;
  }
  Frama_C_show_each_split_with_uninit(a, b);
  a = 0;
  Frama_C_show_each_no_split(a, b);
  a = Frama_C_interval(0, 2);
  b = a;
  //@ split a;
  a = 0;
  Frama_C_show_each_split(a, b);
  //@ merge a;
  Frama_C_show_each_no_split(a, b);
}

void test_dynamic_split_predicate()
{
  int x, y;
  //@ dynamic_split \initialized(&x);
  int c = nondet;
  if (c != 1) {
    x = 42;
  }
  y = 2;
  if (c != 1)
    x += y; // No alarm on x initialization with the dynamic partitioning.
  else {
    for (int i = 0; i < 32; i++)
      x = i;
  }
  y = x; // No alarm on x initialization with the dynamic partitioning.
}

void test_loop_split()
{
  int A[N];
  int i;

  // In this example we can split on the value of the loop index in order to
  // keep the relation between i and the value A[i] found in the array to be
  // equal to 42.
  // However, since the split is not dynamic, a history partitioning must be
  // added to distinguish between the two states that share i = 9 : those who
  // left the loop at the break point and those who left after the loop test.

  // Init a random array
  for (i = 0 ; i < N ; i ++)
  {
    A[i] = Frama_C_interval(0,100);
  }

  // Search for some value
  for (i = 0 ; i < N ; i++)
  {
    //@ split i;
    if (A[i] == 42)
      break;
  }

  if (i < N) {
    Frama_C_show_each(i, A[i]);
    //@ assert A[i] == 42;
  }
  else {
    Frama_C_show_each("Value 42 not found");
  }
}

/*@
   assigns \result, *p \from i;
   behavior error:
     assumes nondet == 0;
     assigns \result, *p \from i;
     ensures \result == -1;
     ensures \initialized(p) && *p == \old(i);
   behavior positive:
     assumes nondet > 0;
     assigns \result \from i;
     ensures \result >= 10;
   behavior negative:
     assumes nondet < 0;
     assigns \result \from i;
     ensures \result <= -10;
   disjoint behaviors;
   complete behaviors;
*/
int spec(int i, int* p);

int body(int i, int *p) {
  int i2 = i / 2;
  int absolute = i2 < 0 ? -i2 : i2;
  int state = nondet % 2;
  //@ split state;
  if (state < 0)
    return - 10 - absolute;
  if (state > 0)
    return 10 + absolute;
  *p = i;
  return -1;
}

/* Tests the application of multiple splits according to the return value of a
   call, to keep in the caller some state partitioning from the callee.
   The splits must be defined after the call, so the state partitioning from the
   callee must be kept until all splits are performed.
   Tests this whether the function body or a specification is used. */
void test_splits_post_call (void) {
  int x, y, error;
  int i = Frama_C_interval(-1000, 1000);
  int r = spec(i, &x);
  //@ split r < -1;
  //@ split r > -1;
  if (r == -1)
    error = x; // There should be no alarm.
  Frama_C_show_each_spec(r, x); // There should be three states.
  r = body(i, &y);
  //@ split r < -1;
  //@ split r > -1;
  if (r == -1)
    error = y; // There should be no alarm.
  Frama_C_show_each_body(r, y); // There should be three states.
}

void test_history()
{
  int i = Frama_C_interval(0,1);
  int j = 0, k = 1;

  if (i)
    j = 1;

  Frama_C_show_each(i, j);

  if (i)
    k = k / j;
}

void test_slevel()
{
  int a[N], b[N], c[N], d[N], e[4];
  //@slevel 10;
  for (int i = 0; i < N; i++) {
    a[i] = 42;
  }

  //@slevel default;
  for (int i = 0; i < N; i++) {
    b[i] = 42;
  }

  //@slevel 20;
  for (int i = 0; i < N; i++) {
    if (nondet)
      c[i] = 42;
    else
      c[i] = 33;
  }

  //@slevel 20;
  for (int i = 0; i < N; i++) {
    if (nondet)
      d[i] = 42;
    else
      d[i] = 33;
    //@slevel merge;
    ; // Otherwise previous annotation is ignored
  }

  //@slevel 0;
  ;
  //@slevel full;
  for (int i = 0; i < 4; i++) {
    if (nondet)
      e[i] = 42;
    else
      e[i] = 33;
  }
}

void test_auto_limit()
{
  // This loop should be unrolled
  //@ loop unroll auto, 30;
  for (int i = 0; i < 20; i++) {}

  // This loop should not be unrolled
  //@ loop unroll auto, 5;
  for (int i = 0; i < 20; i++) {}
}

/*@ assigns \result \from \nothing;
    ensures \result > 0 || \result < 0; */
int non_zero_disjunction(void);

/*@ assigns \result \from x;
    behavior positive:
      assumes x >= 0;
      ensures \result > 0;
    behavior negative:
      assumes x < 0;
      ensures \result < 0;
    complete behaviors;
    disjoint behaviors; */
int non_zero_behavior(int x);

/*@ assigns \result \from *p;
    assigns *p \from *p;
    ensures
      (\result == 0 && 0 < *p <= 10)
      || (\result == 1 && 10 < *p < 100)
      || (\result == -1 && -100 < *p < 0)
      || (\result == -2 && *p == 0) ; */
int more_complex_disjunction(int *p);

/* Use the three function specifications above to test the state partitioning
   on ACSL disjunctions and contract behaviors. */
void test_logic_disjunction(void) {
  int x, y;
  x = non_zero_disjunction();
  y = 100 / x; // Alarm without state partitioning.
  x = non_zero_disjunction();
  //@ split x < 0;
  y = 100 / x; // No alarm.
  //@ merge x < 0;
  x = non_zero_disjunction();
  //@ slevel 2;
  y = 100 / x; // No alarm.
  //@ slevel default;

  x = non_zero_behavior(nondet);
  y = 100 / x; // Alarm without state partitioning.
  x = non_zero_behavior(nondet);
  //@ split x < 0;
  y = 100 / x; // No alarm.
  //@ merge x < 0;
  x = non_zero_behavior(nondet);
  //@ slevel 2;
  y = 100 / x; // No alarm.
  //@ slevel default;

  y = more_complex_disjunction(&x);
  Frama_C_show_each(x, y); // Only 1 state.

  //@ slevel 4;
  y = more_complex_disjunction(&x);
  Frama_C_show_each(x, y); // There should be 4 precise states.
  //@ slevel default;

  y = more_complex_disjunction(&x);
  //@ split y;
  Frama_C_show_each(x, y); // There should be 4 precise states.
}


void test_syntactic_plit()
{
  int i = Frama_C_interval(0,1);
  int j = Frama_C_interval(0,2);
  int k;

  //@ split \cases;
  if (i != j) {
    i = j = 3;
  }

  // This if-then-else should not be impacted by the split annotation above
  if (i == 0) {
    k = 0;
  }
  else {
    k = 1;
  }

  Frama_C_show_each(i, j, k); // Only two states must be printed here

  //@ merge \cases;

  Frama_C_show_each(i, j, k); // Only on state must be printed here
}

void main(void)
{
  test_slevel();
  test_unroll();
  test_split();
  test_dynamic_split();
  test_dynamic_split_predicate();
  test_splits_post_call();
  test_auto_limit();
  test_logic_disjunction();
  test_syntactic_plit();
}
