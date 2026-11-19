# E-ACSL: in `\exists integer n; 0 <= n < size && P && Q`, only `Q` is checked, so a false predicate passes

Draft bug report for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues). Filed on 2026-11-15 as [#2793](https://git.frama-c.com/pub/frama-c/-/work_items/2793); the fix is merge request [!25](https://git.frama-c.com/pub/frama-c/-/merge_requests/25).

**Filing package:** [issue](./filing/24-eacsl-guarded-exists-drops-conjunct-issue.md), [MR](./filing/24-eacsl-guarded-exists-drops-conjunct-mr.md), [reproducer](./repro/24-eacsl-guarded-exists-drops-conjunct.sh), [patch](./patches/24-eacsl-guarded-exists-drops-conjunct.patch)

**Soundness bug.** E-ACSL reports false predicates as valid. Nothing warns.

## Summary

E-ACSL translates a guarded existential quantification with two or more conjuncts after the guard by
checking only the last conjunct. With `size == 5`, this precondition is false (no `n` in `[0, 5)` is
1000), but the instrumented program runs without a failure:

```c
/*@ requires \exists integer n; 0 <= n < size && n == 1000 && n >= 0; */
void two_conjuncts(int size) { }
```

The generated loop tests the guard and `n >= 0` only. `n == 1000` is gone:

```c
    __gen_e_acsl_exists = 0;
    __gen_e_acsl_n = 0;
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

- Every conjunct between the guard and the last one is dropped: with
  `0 <= n < size && n == 1000 && n == 1001 && n >= 0`, only `n >= 0` is checked.
- Parentheses do not help: `0 <= n < size && (n == 1000 && n >= 0)` is translated the same way.
- With the conjuncts swapped (`0 <= n < size && n >= 0 && n == 1000`), the precondition fails, as it
  should, but only because the false conjunct happens to be the last one.
- `\forall integer n; 0 <= n < size ==> P && Q` and right-nested chains
  `\forall integer i, j; 0 <= i < size ==> 0 <= j < size ==> P(i, j)` are translated correctly.
- Related `\forall` forms are translated wrongly too:
  - `\forall integer n; (0 <= n < size ==> P) ==> Q` is checked as `\forall integer n; 0 <= n < size ==> Q`,
    dropping `P` and every `n` outside the range.
  - Multi-variable nested implications inside a hypothesis, such as
    `\forall integer i, j; (0 <= i < size ==> 0 <= j < size) ==> i < size` and
    `\forall integer i, j, k; (0 <= i < size ==> 0 <= j < size) && 0 <= k < size ==> i < size`, are
    checked as `\forall ...; 0 <= i < size && 0 <= j < size ... ==> i < size` (valid), even though the
    original formulas are false for `i == size, j == 0` (and `k == 0`).
  - Conjunctions outside an implication hypothesis while unguarded variables remain, such as
    `\forall integer i, j; 0 <= i < size ==> 0 <= j && (j < size ==> i < size)`, are checked as
    `\forall integer i, j; 0 <= i < size && 0 <= j < size ==> i < size` (valid), even though the
    original formula is false for `i == 0, j == -1`.

This form is common in contracts on buffers: "some index in range satisfies P and Q", for example
`\exists integer i; 0 <= i < n && \valid_read(s + (0 .. i)) && s[i] == '\0'` for a NUL-terminated
string. E-ACSL then checks only `s[i] == '\0'`, not the validity of the bytes before it.

### Cause

The ACSL parser associates conjunctions to the left. `pland` in
`src/kernel/internals/parsing/logic_parser.mly:54-60` even rewrites `p1 && (p2 && p3)` into
`(p1 && p2) && p3`. So `0 <= n < size && P && Q` reaches E-ACSL as
`((0 <= n && n < size) && P) && Q`, whatever the parentheses.

`visit_quantif_relations` (`plugins/e-acsl/src/analyses/bound_variables.ml:578-615`) walks the
quantified predicate from the left to extract the guard. It returns the context and the goal it found,
if any. On `Pand(lhs, rhs)`, it visits `lhs` and ignores the goal that visit returned
(`let ctxt, _ = ...`, line 596). Once the guard is complete, it returns `rhs` as the goal (line 600):

- on `(G && P) && Q`, the inner visit of `G && P` completes the guard and returns `P` as the goal;
- the outer visit discards `P` and returns `Q`.

`Quantif.convert` (`plugins/e-acsl/src/code_generator/quantif.ml:64`) then builds the loop for the
goal `Q`.

For `\forall`, `visit_quantif_relations` also does not track whether it is currently inside the
left-hand side (hypothesis) of a `Pimplies`. Thus:

- inside `lhs` of `Pimplies`, a nested `Pimplies` is treated as if `(A ==> B) ==> C` were
  `(A && B) ==> C`, even when `B` bounds remaining variables (so checking only `Option.is_some lhs_goal`
  is insufficient because the inner `Pimplies` returns `None`);
- outside `lhs` of `Pimplies` (for example on `rhs` of an outer `Pimplies` while another variable is
  still unguarded), a `Pand` is treated as a guard conjunction rather than a consequent conjunction.

## Versions

- Reproduced on Frama-C `35.0~~dev (Bromine)`, `master` at `b80fcac74f` (and previously `3dff90fc70`),
  and on `34.0~beta (Selenium)`, Debian 13, gcc 14.2.0. Same output on all of them.
- The code has not changed in this area since 34. I did not check older releases.

## Reproduction

[`./repro/24-eacsl-guarded-exists-drops-conjunct.c`](./repro/24-eacsl-guarded-exists-drops-conjunct.c)
has eight functions whose precondition is false for `size == 5`. `main` calls one of them, chosen by the
number of arguments. [`./repro/24-eacsl-guarded-exists-drops-conjunct.sh`](./repro/24-eacsl-guarded-exists-drops-conjunct.sh)
builds it with `e-acsl-gcc -X` (instrumented program only) and runs each case. On `master` (`b80fcac74f`),
only `swapped` fails:

```text
35.0~~dev (Bromine)
build: exit 0
two_conjuncts(5): exit 0
three_conjuncts(5): exit 0
parenthesized(5): exit 0
swapped(5): exit 134 24-eacsl-guarded-exists-drops-conjunct.c:13: Error: Precondition failed:
forall_guard_in_hypothesis(5): exit 0
forall_nested_implication(5): exit 0
forall_nested_implication_conj(5): exit 0
forall_conj_after_implication(5): exit 0
```

## Proposed fix

[`./patches/24-eacsl-guarded-exists-drops-conjunct.patch`](./patches/24-eacsl-guarded-exists-drops-conjunct.patch)
(one commit on `fix/eacsl-guarded-quantifier-goal` from `b80fcac74f`, "[e-acsl] check every conjunct
after the guard of a quantification"). In `visit_quantif_relations`:

- Add an optional `?(in_lhs=false)` flag tracking whether traversal is inside the hypothesis of an
  implication in a universal quantification.
- `Pimplies`: when `in_lhs` is `true`, reject unconditionally with `"invalid quantification guard,
  found '⇒' inside the hypothesis of an implication"`. Otherwise, for `\forall`, visit `lhs` with
  `~in_lhs:true`, and if unguarded variables remain, recurse on `rhs` with `in_lhs = false` (so
  right-associative chained implications `0 <= i < n ==> 0 <= j < m ==> P(i, j)` remain accepted).
- `Pand`: when `is_forall && not in_lhs`, reject with `"invalid quantification guard, expecting '⇒' to
  separate the hypotheses from the goal, found '∧'"`. Otherwise propagate `~in_lhs` to both operands of
  `Pand`. For `\exists`, when the visit of `lhs` returned a goal, the goal is
  `Logic_const.pand ~loc:p.pred_loc (lhs_goal, rhs)`. On `((G && P) && Q)`, the goal is `P && Q`; with
  more conjuncts the recursion builds `(P && Q) && R`, and so on.

```diff
-let rec visit_quantif_relations ~is_forall ctxt p =
+let rec visit_quantif_relations ~is_forall ?(in_lhs=false) ctxt p =
   match p.pred_content with
   | Pimplies(lhs, rhs) ->
-    let ctxt, _ = visit_quantif_relations ~is_forall ctxt lhs in
-    if is_forall then begin
+    if in_lhs then begin
+      (* An implication inside the hypothesis of an implication, as in
+         [(0 <= i < n ==> p) ==> q] or [(0 <= i < n ==> 0 <= j < m) ==> q],
+         does not guard the whole quantification. *)
+      let msg =
+        Format.asprintf
+          "@[invalid quantification guard, found '%t'@ \
+           inside the hypothesis of an implication@]"
+          Unicode.pp_implies
+      in
+      Constraints.raise_error msg ctxt
+    end else if is_forall then begin
+      let ctxt, _ = visit_quantif_relations ~is_forall ~in_lhs:true ctxt lhs in
       if Constraints.has_unguarded_bounded_vars ctxt then
         visit_quantif_relations ~is_forall ctxt rhs
       else
         ctxt, Some rhs
     end else
 ...
   | Pand(lhs, rhs) ->
-    let ctxt, _ = visit_quantif_relations ~is_forall ctxt lhs in
-    if Constraints.has_unguarded_bounded_vars ctxt then
-      visit_quantif_relations ~is_forall ctxt rhs
-    else if not is_forall then
-      ctxt, Some rhs
-    else
+    if is_forall && not in_lhs then
+      ...
+      Constraints.raise_error msg ctxt
+    else begin
+      let ctxt, lhs_goal =
+        visit_quantif_relations ~is_forall ~in_lhs ctxt lhs
+      in
+      if Constraints.has_unguarded_bounded_vars ctxt then
+        visit_quantif_relations ~is_forall ~in_lhs ctxt rhs
+      else if not is_forall then
+        (* The parser associates conjunctions to the left:
+           [0 <= i < n && p && q] is [((0 <= i < n) && p) && q]. If the goal
+           started inside [lhs] ([p] here), [rhs] is its last conjunct. *)
+        let goal = match lhs_goal with
+          | None -> rhs
+          | Some lhs_goal -> Logic_const.pand ~loc:p.pred_loc (lhs_goal, rhs)
+        in
+        ctxt, Some goal
+      else
+        ...
+    end
```

The goal is stored in the `Quantifier` table, which typing, interval inference, label analysis and
`Quantif.convert` all read, so they all work on the same predicate.

The patch adds the regression test `plugins/e-acsl/tests/constructs/quantif_conjunctions.c` with its
oracles. It asserts true predicates whose translation was wrong: `!(\exists ...)` with a false
conjunct before the last one fails at run time without the change. It also covers two bound variables
for `\exists`, positive controls for `\forall ... ==> P && Q` and right-nested chained implications
`0 <= i < size ==> 0 <= j < size ==> i + j < 2 * size`, and the rejected `\forall` forms
(single-variable and multi-variable nested implications inside a hypothesis, nested implication in a
hypothesis conjunction, and conjunction outside a hypothesis).

## Validation of the proposed fix

`master` at `b80fcac74f` in a fresh `framac-master-audit:b80fcac` container, validated with
`JOBS=4 /w/revalidate.sh before 24` and `JOBS=4 /w/revalidate.sh package 24` (Debian 13, gcc 14.2.0):

| Check | `master` (`b80fcac74f`) | Patched |
|---|---|---|
| `two_conjuncts`, `three_conjuncts`, `parenthesized` | exit 0 (false precondition passes) | `Precondition failed`, exit 134 |
| `swapped` | `Precondition failed`, exit 134 | `Precondition failed`, exit 134 |
| `forall_guard_in_hypothesis`, `forall_nested_implication`, `forall_nested_implication_conj` | checked as `G ==> Q`, exit 0 | rejected with `"invalid quantification guard, found '⇒' inside the hypothesis of an implication"`, not checked, exit 0 |
| `forall_conj_after_implication` | checked as `G ==> Q`, exit 0 | rejected with `"invalid quantification guard, expecting '⇒' to separate the hypotheses from the goal, found '∧'"`, not checked, exit 0 |
| New test `constructs/quantif_conjunctions.c` (default) | fails (exit 1) | passes (exit 0) |
| New test `constructs/quantif_conjunctions.c` (`dev`, compiled and run) | fails at run time (exit 1) | passes (exit 0) |
| Full E-ACSL suite `./dev/test.sh -p plugins/e-acsl` | — | passes (exit 0); no existing oracle changes |
| `./dev/check-files.sh -p HEAD~1` (lint: `ocp-indent`, `clang-format` 19.1.7; headers) | — | passes on all 4 files (exit 0) |

## Workaround

Write exactly one predicate after the guard. Either put the conjuncts in a predicate,
`\exists integer n; 0 <= n < size && p(n)` with `predicate p(integer n) = P && Q;`, or parenthesize
them inside something that is not a conjunction at the top. The pipeline does the former in its stubs
([`../../troubleshooting/eacsl-and-fuzzing.md`](../../troubleshooting/eacsl-and-fuzzing.md), "An E-ACSL
`\exists` Passes Although One of Its Conjuncts Is False"): each E-ACSL quantifier in the stub headers
calls one predicate after its guard, and
[`../../../tests/test_fc_stub_repairs.py`](../../../tests/test_fc_stub_repairs.py) enforces it. Contracts
written by hand or by provers are not covered.

## Tracker

No match in the 202 open issues of the 2026-11-09 export
([`./pub-frama-c_work_items_2026-11-09.csv`](./pub-frama-c_work_items_2026-11-09.csv)): I searched titles
and descriptions for `\exists`, `quantif`, `conjun`. A live search of git.frama-c.com on 2026-11-15 found
no duplicate either.
