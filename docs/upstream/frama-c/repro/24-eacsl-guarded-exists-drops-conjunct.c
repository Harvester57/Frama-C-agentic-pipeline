/* Every precondition below is false when size == 5. */

/*@ requires \exists integer n; 0 <= n < size && n == 1000 && n >= 0; */
void two_conjuncts(int size) { }

/*@ requires \exists integer n; 0 <= n < size && n == 1000 && n == 1001 && n >= 0; */
void three_conjuncts(int size) { }

/*@ requires \exists integer n; 0 <= n < size && (n == 1000 && n >= 0); */
void parenthesized(int size) { }

/* control: the false conjunct comes last */
/*@ requires \exists integer n; 0 <= n < size && n >= 0 && n == 1000; */
void swapped(int size) { }

/* false for n == size: the hypothesis holds, n < size does not */
/*@ requires \forall integer n; (0 <= n < size ==> n == 1000) ==> n < size; */
void forall_guard_in_hypothesis(int size) { }

int main(int argc, char **argv)
{
  (void)argv;
  switch (argc) {
  case 1: two_conjuncts(5); break;
  case 2: three_conjuncts(5); break;
  case 3: parenthesized(5); break;
  case 4: swapped(5); break;
  default: forall_guard_in_hypothesis(5); break;
  }
  return 0;
}
