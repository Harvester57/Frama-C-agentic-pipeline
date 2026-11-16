# [E-ACSL] In `\exists integer n; 0 <= n < size && P && Q`, only `Q` is checked, so a false predicate passes

<!-- Everything below this line is the issue description. -->

### Summary

E-ACSL checks a guarded quantification such as `\exists integer n; 0 <= n < size && P && Q` as if it were `\exists integer n; 0 <= n < size && Q`: every conjunct between the guard and the last one is dropped, even inside parentheses. A false predicate can therefore pass the runtime check, with no warning, so this is a soundness issue. In `\forall integer n; (0 <= n < size ==> P) ==> Q`, `P` is dropped the same way.

### Steps to reproduce the issue

`t.c`: each precondition is false for `size == 5`; `main` calls one function, chosen by the number of
arguments.

```c
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
```

```sh
e-acsl-gcc -q -X -o t.inst.c -O t t.c
for args in "" "x" "x x" "x x x" "x x x x"; do ./t.e-acsl $args; echo "exit $?"; done
```

### Expected behaviour

All five preconditions are false, so each run stops with `Precondition failed`, or E-ACSL warns at
instrumentation time that it cannot translate the predicate.

### Actual behaviour

Only the fourth run (`swapped`) fails. E-ACSL prints no warning at instrumentation time, and the other
runs exit 0:

```text
exit 0
exit 0
exit 0
t.c: In function 'swapped'
t.c:13: Error: Precondition failed:
	The failing predicate is:
	∃ ℤ n; 0 ≤ n < size ∧ n ≥ 0 ∧ n ≡ 1000.
	With values at failure point:
	- ∃ ℤ n; 0 ≤ n < size ∧ n ≥ 0 ∧ n ≡ 1000: 0
exit 134
exit 0
```

The loop generated for `two_conjuncts` tests the guard and `n >= 0` only; `n == 1000` is gone:

```c
    while (1) {
      if (__gen_e_acsl_n < size) ; else break;
      if (! (__gen_e_acsl_n >= 0)) ;
      else {
        __gen_e_acsl_exists = 1;
        goto e_acsl_end_loop1;
      }
      __gen_e_acsl_n ++;
    }
```

Every conjunct between the guard and the last one is dropped, even inside parentheses. `swapped` fails
only because its false conjunct is the last one. For `forall_guard_in_hypothesis`, E-ACSL checks
`\forall integer n; 0 <= n < size ==> n < size`.

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at 3dff90fc70; also 34.0~beta (Selenium)
- Plug-in used: E-ACSL (`e-acsl-gcc`)
- OS name: Debian GNU/Linux
- OS version: 13 (trixie)

### Additional information (optional)

**Cause.** The parser associates conjunctions to the left; `pland`
(`src/kernel/internals/parsing/logic_parser.mly:54-60`) even rewrites `p1 && (p2 && p3)` into
`(p1 && p2) && p3`. So `0 <= n < size && P && Q` reaches E-ACSL as `((0 <= n && n < size) && P) && Q`.
`visit_quantif_relations` (`plugins/e-acsl/src/analyses/bound_variables.ml:578-615`) extracts the guard
from the left. On `Pand(lhs, rhs)`, it discards the goal returned by the visit of `lhs`
(`let ctxt, _ = ...`, line 596) and returns `rhs` once the guard is complete (line 600). On
`(G && P) && Q`, the inner visit returns `P`, the outer one drops it and returns `Q`. The `Pimplies`
case (line 581) drops the goal of its left operand the same way, which turns
`(G ==> P) ==> Q` into `G ==> Q`.

**Fix.** When the visit of `lhs` returned a goal, the goal of `Pand(lhs, rhs)` is the conjunction of that
goal and `rhs`. When the left operand of an implication already contains the whole guard, the guard does
not bound the quantification: reject the predicate as for the other invalid guards. A merge request with
a fix follows.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
