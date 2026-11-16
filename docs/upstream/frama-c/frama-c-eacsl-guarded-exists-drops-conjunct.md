# E-ACSL: in `\exists integer n; 0 <= n < size && P && Q`, only `Q` is checked, so a false predicate passes

Draft bug report for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues). Filed on 2026-11-15 as [#2793](https://git.frama-c.com/pub/frama-c/-/work_items/2793); the fix is merge request [!25](https://git.frama-c.com/pub/frama-c/-/merge_requests/25).

**Filing package:** [issue](./filing/24-eacsl-guarded-exists-drops-conjunct-issue.md), [MR](./filing/24-eacsl-guarded-exists-drops-conjunct-mr.md), [reproducer](./repro/24-eacsl-guarded-exists-drops-conjunct.sh), [patch](./patches/24-eacsl-guarded-exists-drops-conjunct.patch)

**Soundness bug.** E-ACSL reports a false predicate as valid. Nothing warns.

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
- `\forall integer n; 0 <= n < size ==> P && Q` is translated correctly (`P && Q` is the right
  operand of the implication).
- A related form is translated wrongly too: `\forall integer n; (0 <= n < size ==> P) ==> Q` is
  checked as `\forall integer n; 0 <= n < size ==> Q`. `P` is dropped, and so is every `n` outside the
  range, for which the hypothesis is true. `\forall integer n; (0 <= n < size ==> n == 1000) ==> n < size`
  is false for `n == size`, and passes.

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
goal `Q`. The `Pimplies` case (line 581) discards the goal of its left operand the same way, which gives
the `(G ==> P) ==> Q` mistranslation.

## Versions

- Reproduced on Frama-C `35.0~~dev (Bromine)`, `master` at `3dff90fc70` (2026-11-13), and on
  `34.0~beta (Selenium)`, Debian 13, gcc 14.2.0. Same output on both.
- The code has not changed in this area since 34. I did not check older releases.

## Reproduction

[`./repro/24-eacsl-guarded-exists-drops-conjunct.c`](./repro/24-eacsl-guarded-exists-drops-conjunct.c)
has five functions whose precondition is false for `size == 5`. `main` calls one of them, chosen by the
number of arguments. [`./repro/24-eacsl-guarded-exists-drops-conjunct.sh`](./repro/24-eacsl-guarded-exists-drops-conjunct.sh)
builds it with `e-acsl-gcc -X` (instrumented program only) and runs each case. On master (34.0~beta
prints the same, with its version), only `swapped` fails:

```text
35.0~~dev (Bromine)
build: exit 0
two_conjuncts(5): exit 0
three_conjuncts(5): exit 0
parenthesized(5): exit 0
swapped(5): exit 134 24-eacsl-guarded-exists-drops-conjunct.c:13: Error: Precondition failed:
forall_guard_in_hypothesis(5): exit 0
```

## Proposed fix

[`./patches/24-eacsl-guarded-exists-drops-conjunct.patch`](./patches/24-eacsl-guarded-exists-drops-conjunct.patch)
(one commit on `fix/eacsl-guarded-quantifier-goal` from `3dff90fc70`, "[e-acsl] check every conjunct
after the guard of a quantification"). In `visit_quantif_relations`:

- `Pand`: when the visit of the left operand returned a goal, the goal is that goal and the right
  operand, `Logic_const.pand (lhs_goal, rhs)`. On `((G && P) && Q)`, the goal is `P && Q`; with more
  conjuncts the recursion builds `(P && Q) && R`, and so on.
- `Pimplies`: when the left operand already contains the end of the guard, as in
  `(G ==> P) ==> Q`, the guard does not bound the quantification. The predicate is rejected with
  "invalid quantification guard, found '⇒' after the end of the guard of an hypothesis", like the
  other unsupported guards: E-ACSL warns and does not check the annotation, instead of checking a
  weaker predicate.

```diff
   | Pimplies(lhs, rhs) ->
-    let ctxt, _ = visit_quantif_relations ~is_forall ctxt lhs in
-    if is_forall then begin
+    let ctxt, lhs_goal = visit_quantif_relations ~is_forall ctxt lhs in
+    if Option.is_some lhs_goal then begin
+      (* the guards end inside [lhs], as in [(0 <= i < n ==> p) ==> q]: they do
+         not guard the whole predicate *)
+      let msg =
+        Format.asprintf
+          "@[invalid quantification guard, found '%t'@ \
+           after the end of the guard of an hypothesis@]"
+          Unicode.pp_implies
+      in
+      Constraints.raise_error msg ctxt
+    end else if is_forall then begin
 ...
   | Pand(lhs, rhs) ->
-    let ctxt, _ = visit_quantif_relations ~is_forall ctxt lhs in
+    let ctxt, lhs_goal = visit_quantif_relations ~is_forall ctxt lhs in
     if Constraints.has_unguarded_bounded_vars ctxt then
       visit_quantif_relations ~is_forall ctxt rhs
     else if not is_forall then
-      ctxt, Some rhs
+      (* The parser associates conjunctions to the left:
+         [0 <= i < n && p && q] is [((0 <= i < n) && p) && q]. If the goal
+         started inside [lhs] ([p] here), [rhs] is its last conjunct. *)
+      let goal = match lhs_goal with
+        | None -> rhs
+        | Some lhs_goal -> Logic_const.pand ~loc:p.pred_loc (lhs_goal, rhs)
+      in
+      ctxt, Some goal
```

The goal is stored in the `Quantifier` table, which typing, interval inference, label analysis and
`Quantif.convert` all read, so they all work on the same predicate.

The patch adds the regression test `plugins/e-acsl/tests/constructs/quantif_conjunctions.c` with its
oracles. It asserts true predicates whose translation was wrong: `!(\exists ...)` with a false
conjunct before the last one fails at run time without the change. It also covers two bound variables,
the `\forall ... ==> P && Q` form (unchanged) and the rejected implication form.

## Validation of the proposed fix

`master` at `3dff90fc70` in `framac-master-audit:3dff90f`, then the same tree with the patch, rebuilt
with dune and installed (Debian 13, gcc 14.2.0).

| Check | `master` | Patched |
|---|---|---|
| `two_conjuncts`, `three_conjuncts`, `parenthesized` | exit 0 (false precondition passes) | `Precondition failed`, exit 134 |
| `swapped` | `Precondition failed`, exit 134 | `Precondition failed`, exit 134 |
| `forall_guard_in_hypothesis` | checked as `G ==> Q`, exit 0 | rejected with "invalid quantification guard ... after the end of the guard of an hypothesis", not checked, exit 0 |
| New test `constructs/quantif_conjunctions.c` | fails at run time (line 10) | passes, default and `dev` configurations |
| ptests `plugins/e-acsl/tests`, default configuration (198 results) | — | only the new oracles; every other test matches its oracle |
| ptests, `dev` configuration (compiled and run) in every directory but `libc/` and `format/` (188 results) | — | all match `oracle_dev` |
| `git diff --check` | — | clean in the source and the test; the generated oracles have the trailing space after `Warning:` and the final blank line that every E-ACSL oracle has |
| `ocp-indent` 1.9.0, repository `.ocp-indent` | — | `bound_variables.ml` unchanged |
| `make check-lint`, `make check-headers` | — | not run: the image's tree is not a git checkout |

Not completed: the `dev` configuration of `libc/` and `format/`. Their tests abort child processes on
purpose, and the crash handler of the Docker host (`core_pattern` piped to a WSL crash collector) made
`format/printf.c` exceed a 40-minute timeout. Their default configuration ran and matches the oracles.

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
