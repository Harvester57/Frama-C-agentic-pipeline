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

/* false for i == size, j == 0: the hypothesis holds, i < size does not */
/*@ requires \forall integer i, j; (0 <= i < size ==> 0 <= j < size) ==> i < size; */
void forall_nested_implication(int size) { }

/* false for i == size, j == 0, k == 0 */
/*@ requires \forall integer i, j, k; (0 <= i < size ==> 0 <= j < size) && 0 <= k < size ==> i < size; */
void forall_nested_implication_conj(int size) { }

/* false for i == 0, j == -1: 0 <= j is false in the consequent */
/*@ requires \forall integer i, j; 0 <= i < size ==> 0 <= j && (j < size ==> i < size); */
void forall_conj_after_implication(int size) { }

int main(int argc, char **argv)
{
  (void)argv;
  switch (argc) {
  case 1: two_conjuncts(5); break;
  case 2: three_conjuncts(5); break;
  case 3: parenthesized(5); break;
  case 4: swapped(5); break;
  case 5: forall_guard_in_hypothesis(5); break;
  case 6: forall_nested_implication(5); break;
  case 7: forall_nested_implication_conj(5); break;
  default: forall_conj_after_implication(5); break;
  }
  return 0;
}
