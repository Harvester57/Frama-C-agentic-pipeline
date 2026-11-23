# [WP] Adding or subtracting integer ranges (`Vset.ml`) and shifting pointer ranges (`Cvalues.ml`) ignore empty ranges and prove false properties

<!-- Everything below this line is the issue description. -->

### Summary

When adding or subtracting two integer ranges `(a..b)` and `(c..d)` in `Vset.ml` (`lift_add`, `lift_sub`), or when shifting a pointer range `p + (a..b)` by another range `(c..d)` in `Cvalues.ml` (`shift_set`), WP folds the two ranges bound-by-bound into `(a+c .. b+d)` (or `(a-d .. b-c)`) without preserving the requirement that both operand ranges be non-empty (`a <= b` and `c <= d`).

When one operand is empty (either statically like `5..3` or under a hypothesis like `0 .. n-1` with `n == 0`), the folded bounds can become non-empty. As a result, WP proves false set memberships, refutes `\subset(..., \empty)`, derives `\valid(p)` from an empty validity precondition, and accepts out-of-footprint writes under an empty `assigns` clause.

### Steps to reproduce the issue

`empty_range.c`:

```c
/*@ check lemma empty_plus:   8 \in ((5..3) + (0..10));
    check lemma empty_minus: -2 \in ((5..3) - (0..10));
    check lemma open_empty:   0 \in ((..3) + (5..4));
    check lemma subset_empty: \subset((5..3) + (0..10), \empty); */

/*@ requires n == 0;
    ensures 5 \in ((0 .. n - 1) + (0 .. 10)); */
void g(int n) {}

/*@ requires n == 0;
    requires \valid(p + (0 .. n - 1) + (0 .. 1));
    assigns \nothing; */
void w2(int *p, int n) {
  /*@ check f_valid2: \valid(p); */
}

/*@ requires n == 0;
    assigns f_assigns3: *(p + (0 .. n - 1) + (0 .. 1)); */
void w3(int *p, int n) { *p = 1; }

/*@ requires n == 0;
    assigns f_assigns5: *(p + (0 .. n - 1) + 0); */
void w5(int *p, int n) { *p = 1; }
```

```sh
frama-c -wp -wp-prover none -wp-print empty_range.c
frama-c -wp -wp-prover alt-ergo empty_range.c
```

### Expected behaviour

In ACSL, a range `t1..t2` with `t1 > t2` is equivalent to `\empty`, and any operation lifted over `\empty` yields `\empty`:

- `empty_plus`, `empty_minus`, `open_empty`, and the postcondition of `g` are false and should simplify to `Prove: false.`.
- `subset_empty` is true and should simplify to `Prove: true.`.
- In `w2`, with `n == 0` the precondition `\valid(p + (0 .. -1) + (0 .. 1))` covers an empty set of locations and says nothing about `p`; `f_valid2` must remain unproved.
- In `w3`, with `n == 0` the `assigns` clause is empty and `*p = 1;` must be rejected (`Prove: false.`), just as in the singleton-shift control `w5`.

### Actual behaviour

With `-wp -wp-prover none -wp-print`:

```text
Goal Check Lemma 'empty_minus':
Prove: true.

Goal Check Lemma 'empty_plus':
Prove: true.

Goal Check Lemma 'open_empty':
Prove: true.

Goal Check Lemma 'subset_empty':
Assume { Have: 5 <= i. Have: i <= 13. }
Prove: false.

Goal Post-condition ("empty_range.c", line 7) in 'g':
Prove: true.

Goal Check 'f_valid2' ("empty_range.c", line 14):
Assume {
  (* Heap *)
  Type: (region(p.base) <= 0) /\ linked(Malloc_0).
  (* Pre-condition *)
  Have: valid_rw(Malloc_0, shift_sint32(p, 0), 1).
}
Prove: valid_rw(Malloc_0, p, 1).

Goal Assigns 'f_assigns3' in 'w3':
Effect at line 19
Prove: true.

Goal Assigns 'f_assigns5' in 'w5':
Effect at line 23
Assume {
  (* Heap *)
  Type: (region(p.base) <= 0) /\ linked(Malloc_0).
  (* Goal *)
  When: !invalid(Malloc_0, p, 1).
}
Prove: false.
```

With `-wp -wp-prover alt-ergo`, Alt-Ergo proves `typed_w2_check_f_valid2` from the spurious `valid_rw` hypothesis, and Qed proves `empty_plus`, `empty_minus`, `open_empty`, `g`'s postcondition, and `w3`'s `assigns` (`Proved goals: 15 / 17`, with the true lemma `subset_empty` and control `w5` remaining `Unknown`).

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at `189053d4a2`; also 34.0~beta (Selenium), with identical output
- Plug-in used: WP
- OS name: Debian GNU/Linux
- OS version: 13 (trixie; glibc 2.41, gcc 14.2.0)

### Additional information (optional)

**Cause.** Two sites share the same unguarded `Vset.bound_add` / `Vset.bound_sub` folding on `189053d4a2`:

1. `plugins/wp/src/Vset.ml`: `lift_add` (lines 362-363) folds `Range(a,b), Range(c,d)` to `Range(bound_add a c, bound_add b d)`, and `lift_sub` (lines 376-377) folds `Range(a,b), Range(c,d)` to `Range(bound_sub a d, bound_sub b c)`.
2. `plugins/wp/src/Cvalues.ml`: `shift_set` (lines 804-808, the sole external caller of `Vset.bound_add`) folds `Srange(l,obj0,a0,b0), Vset.Range(a1,b1)` to `srange l obj0 size (bound_add a0 a1) (bound_add b0 b1)`.

(Shifting a single range by a singleton `k` is unaffected because `a > b` implies `a + k > b + k`.)

**Fix.** Fold two ranges directly to `Range`/`Srange` only when both operands are statically non-empty (open bound or `p_leq a b` simplifies to `Yes`); return an empty range when either is statically empty (`No`); otherwise emit a single-variable comprehension (`Descr`/`Sdescr`) guarded by `non_empty_range a b && non_empty_range c d`. A merge request follows.

The analysis and fix were prepared with LLM assistance; I reviewed them and ran the reproducer and tests described above.
