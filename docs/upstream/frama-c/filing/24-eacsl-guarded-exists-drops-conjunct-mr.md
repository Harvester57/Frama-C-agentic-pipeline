# [e-acsl] check every conjunct after the guard of a quantification

- Source branch: `fix/eacsl-guarded-quantifier-goal` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `b80fcac74f`. Patch: [`../patches/24-eacsl-guarded-exists-drops-conjunct.patch`](../patches/24-eacsl-guarded-exists-drops-conjunct.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #2793.

## Problem

E-ACSL checks only the last conjunct of `\exists integer n; 0 <= n < size && P && Q`. The parser
associates conjunctions to the left (`pland` in `logic_parser.mly` even re-associates
`G && (P && Q)`), so the predicate is `((0 <= n && n < size) && P) && Q`. In
`Bound_variables.visit_quantif_relations`, the visit of the left operand `(G && P)` completes the guard
and returns `P` as the goal; the `Pand` case discards it (`let ctxt, _ = ...`) and returns `Q`. A false
predicate such as `\exists integer n; 0 <= n < 5 && n == 1000 && n >= 0` passes at run time.

In universal quantifications, `visit_quantif_relations` also fails to distinguish guards inside the
hypothesis of an implication from top-level/consequent positions:

- An implication inside an implication hypothesis, whether single-variable
  `\forall integer n; (0 <= n < size ==> P) ==> Q` or multi-variable
  `\forall integer i, j; (0 <= i < size ==> 0 <= j < size) ==> i < size` and
  `\forall integer i, j, k; (0 <= i < size ==> 0 <= j < size) && 0 <= k < size ==> i < size`, is
  treated as if `(A ==> B) ==> C` were `(A && B) ==> C`, turning false predicates into valid ones.
- A conjunction outside an implication hypothesis while unguarded variables remain, as in
  `\forall integer i, j; 0 <= i < size ==> 0 <= j && (j < size ==> i < size)`, is treated as if
  `0 <= j` were a hypothesis rather than a conjunct of the consequent.

## Change

`plugins/e-acsl/src/analyses/bound_variables.ml`, `visit_quantif_relations`:

- Add an optional `?(in_lhs=false)` parameter tracking whether traversal is inside the hypothesis of
  an implication in a universal quantification.
- `Pimplies`: if `in_lhs` is `true`, reject unconditionally with `"invalid quantification guard, found
  '==>' inside the hypothesis of an implication"`. Otherwise, when `is_forall` is `true`, visit `lhs`
  with `~in_lhs:true` and, if unguarded variables remain, recurse on `rhs` with `in_lhs = false` so
  right-nested chained implications (`0 <= i < n ==> 0 <= j < m ==> P(i, j)`) remain accepted.
- `Pand`: if `is_forall && not in_lhs`, reject with `"invalid quantification guard, expecting '==>' to
  separate the hypotheses from the goal, found '&&'"`. Otherwise propagate `~in_lhs` to both operands
  of `Pand`; when `not is_forall` and the visit of `lhs` returned a goal, combine it with `rhs` via
  `Logic_const.pand`. The resulting goal is stored in the `Quantifier` table, which typing, interval
  inference, label analysis and `Quantif.convert` all read.

The new test `constructs/quantif_conjunctions.c` asserts true predicates whose translation was wrong
before (`!(\exists ...)` with a false middle conjunct fails at run time without the change), a
positive right-nested chained-implication control (`0 <= i < size ==> 0 <= j < size ==> i + j < 2 * size`),
and the rejected `\forall` forms (single-variable and multi-variable nested implications inside a
hypothesis, nested implication inside a hypothesis conjunction, and conjunction outside a hypothesis).

## Testing

All on Debian 13 (gcc 14.2.0), `master` at `b80fcac74f` built with dune, then the same tree with this
patch:

- Reproducer from the issue, built with `e-acsl-gcc -X` and run: on pristine `master`, only `swapped`
  fails (exit 134) and the other seven false preconditions silently exit 0. With the patch, all four
  `\exists` preconditions fail with `Precondition failed` (exit 134), and all four invalid `\forall`
  preconditions are rejected at instrumentation time with an `"invalid quantification guard"` warning
  (not checked, run exit 0).
- New test `plugins/e-acsl/tests/constructs/quantif_conjunctions.c`: fails on `master` in both the
  default configuration (oracle diff, no warnings for the invalid `\forall` forms, dropped conjuncts)
  and the `dev` configuration (runtime assertion failure on line 10); passes with the patch in both
  the default and `dev` configurations.
- Full E-ACSL default test suite (`./dev/test.sh -p plugins/e-acsl`): passes with exit 0; no existing
  oracle changes.
- `./dev/check-files.sh -p HEAD~1` (lint including `ocp-indent` and `clang-format` 19.1.7, plus
  header checks): passes on all 4 files (exit 0).

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
