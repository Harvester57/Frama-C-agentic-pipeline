# E-ACSL: `<==>` over a labelled term (`\old`, `\at`, or a formal in a postcondition) aborts with `labels pre-analysis was not performed` (regression in 34.0~beta and 35)

**Filed upstream on 2026-11-15:** issue [#2800](https://git.frama-c.com/pub/frama-c/-/work_items/2800), merge request [!31](https://git.frama-c.com/pub/frama-c/-/merge_requests/31).

Draft for the Frama-C tracker (https://git.frama-c.com/pub/frama-c/-/issues). Listed as Issue 14 in
[`frama-c-e-acsl-issues.md`](./frama-c-e-acsl-issues.md#issue-14-iff-over-a-labelled-term-aborts-the-translation).

**Filing package:** [issue](./filing/14-eacsl-iff-labelled-term-issue.md), [MR](./filing/14-eacsl-iff-labelled-term-mr.md), [reproducer](./repro/14-eacsl-iff-labelled-term.sh), [patch](./patches/14-eacsl-iff-labelled-term.patch)

## Summary

In `35.0~~dev (Bromine)`, E-ACSL stops with a fatal error on any `p1 <==> p2` whose operands contain
a labelled term. That covers an explicit `\old(...)` or `\at(..., L)`, and also a formal parameter in
an `ensures` clause, which the kernel reads as `\old(b)`. A one-line contract a prover writes often
(`ensures (\result != 0) <==> (b->n == 0);`) is enough:

```
[e-acsl] Failure: labels pre-analysis was not performed on construct \old(b)
```

`34.0~~dev (Selenium)` instruments and runs the same programs. The same predicate written as
`(p1 ==> p2) && (p2 ==> p1)`, or with `^^`, `==>` or `||`, works in 35.

### Cause

The non-interlang translation of `Piff` in
`plugins/e-acsl/src/code_generator/translate_predicates.ml:177-189` (35 image source) rewrites
`p1 <==> p2` as `(p1 ==> p2) && (p2' ==> p1')`, where `p1'` and `p2'` are fresh copies from
`Terms.Id.deep_copy_predicate`. The copies get the RTE pre-analysis
(`Rte_analysis.preprocess_predicate`) and typing, but not the labels pre-analysis. The labels
pre-analysis (`analyses/labels.ml`) runs once over the whole file (`Labels.preprocess : file -> unit`)
and records each labelled term in `at_data_for_pots`, a table keyed by term identity. A copied
`\old(b)` has a new identity, so `Labels.at_for_pot` (`labels.ml:106`) finds nothing, and
`Translate_ats.to_exp` (`translate_ats.ml:502` on `master`, 504 in the 35 image) raises the fatal
error. The line numbers of `translate_predicates.ml` and `labels.ml` are the same on `master`
`3dff90fc70`.

In 34.0~~dev the rewrite reused `p1` and `p2` without copying:

```ocaml
| Piff(p1, p2) ->
  let rewritten = (* (p1 <==> p2) <==> (p1 ==> p2 && p2 ==> p1) *)
    Logic_const.pand ~loc
      (Logic_const.pimplies ~loc (p1, p2),
       Logic_const.pimplies ~loc (p2, p1))
  in
```

a9a91e590f added (the commit also adds an `\aligned(q,4)` guard to the second evaluation of `q` in
`memory/oracle/gen_objects.0.c`, which shows what the copies were for: with the shared `p1` and
`p2`, the RTE guards of the second occurrence were missing):

```ocaml
    let p1' = Terms.Id.deep_copy_predicate p1 in
    let p2' = Terms.Id.deep_copy_predicate p2 in
    Rte_analysis.preprocess_predicate ~kf p1';
    Rte_analysis.preprocess_predicate ~kf p2';
    Logic_const.pand ~loc
      (Logic_const.pimplies ~loc (p1, p2),
       Logic_const.pimplies ~loc (p2', p1'))
```

Loop invariants are also deep-copied (`translate_annots.ml:79`), but none of the loop-invariant
cases below fail, including `<==>` with `\at(n, Pre)`.

## Versions

| | Result |
|---|---|
| `35.0~~dev (Bromine)`, `master` at `3dff90fc70`, image `framac-master-audit:3dff90f` | **fails** (`ensures` with a formal, `assert` with `\at`) |
| `35.0~~dev (Bromine)`, image `framac-analysis:latest` (pipeline image, 2026-11-08) | **fails** |
| `34.0~beta (Selenium)`, image `framac-analysis:fc34` | **fails** (same message, reproducer below) |
| `34.0~~dev (Selenium)`, image `framac-pipeline:fc34-20261105` | works |

Debian 13, clang 19 / gcc 14, default `e-acsl-gcc` options. The copies were introduced by
a9a91e590f ("[e-acsl] minor optimisation for the RTE analysis and fix 'Piff' rewriting"), which is
in 34.0~beta.

## Reproduction

```c
struct s { int n; };
/*@ requires \valid_read(b);
    assigns \nothing;
    ensures (\result != 0) <==> (b->n == 0); */
int f(struct s *b) { return b->n == 0; }

int main(void) { struct s x = { 0 }; return f(&x) - 1; }
```

```
$ e-acsl-gcc -c -O single single.c
[e-acsl] Failure: labels pre-analysis was not performed on construct \old(b)
```

The backtrace runs `Translate_predicates.predicate_content_to_exp_old` →
`Translate_terms.to_exp_old` → `tlval_to_lval` → `thost_to_host` → `Translate_ats.to_exp`.

The same failure occurs when the contract is split between a prototype and the definition, or sits
on the prototype only.

Which predicates fail (the same `f`, one `ensures` each; 34 builds all of them):

| `ensures` | 35 |
|---|---|
| `(\result != 0) <==> (b->n == 0)` | **fails** (`\old(b)`) |
| `(x == 0) <==> (\result != 0)` (`int x` formal) | **fails** |
| `(b != \null) <==> (\result != 0)` | **fails** |
| `(b->n == 0) <==> (b->n == 0)` | **fails** |
| `(\old(b->n) == 0) <==> (\result != 0)` | **fails** |
| `(\result != 0) <==> \true` | ok (no labelled term) |
| `((b->n == 0) ==> (\result != 0)) && ((\result != 0) ==> (b->n == 0))` | ok |
| `(b->n == 0) ^^ (\result == 0)` | ok |
| `b->n == 0`, `b->n == 0 ==> \result != 0`, `\old(b)->n == 0`, `\old(b->n) == 0 ==> \result != 0` | ok |

A body assertion fails the same way:

```c
int f(struct s *b) {
  int r = b->n == 0; b->n = 5;
  /*@ assert (r != 0) <==> (\at(b->n, Pre) == 0); */
  return r;
}
```

```
[e-acsl] Failure: labels pre-analysis was not performed on construct \at(b->n,Pre)
```

Loop invariants `s == i && n == \at(n, Pre)`, `s == \at(s, LoopEntry) + i` and
`(s == 0) <==> (i == 0 && n == \at(n, Pre))` build and run on both versions.

## Fix

Two ways were considered:

1. Translate `p1` and `p2` once and combine the two C expressions, as the interlang `Piff` case
   (`translate_predicates.ml:65`) already does: `e1 = to_exp p1`, `e2 = to_exp p2`, result
   `!e1 == !e2`. No copies are needed, and each operand's RTE guards are generated once.
2. Keep the copies, but give their labelled terms the original terms' entries in
   `at_data_for_pots`. `Labels` exposes only `preprocess : file -> unit`, so this needs a new API
   (map a copy onto its original). The other copy sites (`translate_predicates.ml:426`,
   `interlang_trans.ml:400`) copy a predicate only to print it in the generated annotation, not to
   translate it, so there is no mechanism to reuse.

Option 1 was chosen. In the rewriting `(p1 ==> p2) && (p2' ==> p1')`, both operands are always
evaluated: `p1` in the first conjunct, and `p2` in the first conjunct when `p1` holds or in the
second one otherwise. Evaluating each operand once, unconditionally, therefore keeps the semantics,
including when an operand's RTE guard fails, and still gives each operand its guards (the point of
a9a91e590f).

Patch: [`./patches/14-eacsl-iff-labelled-term.patch`](./patches/14-eacsl-iff-labelled-term.patch)
(subject `[e-acsl] translate both operands of <==> once, without copies`, branch
`fix/eacsl-iff-labels` from `3dff90fc70`). The `Piff` case of `predicate_content_to_exp_old` becomes:

```ocaml
  | Piff(p1, p2) ->
    let e1, adata, env = to_exp ~adata kf env p1 in
    let e2, adata, env = to_exp ~adata kf env p2 in
    Misc.make_binop ~loc Eq (Smart_exp.lnot ~loc e1) (Smart_exp.lnot ~loc e2),
    adata,
    env
```

In the regression test below, `ensures (\result != 0) <==> (\old(b->n) == 0);` is now checked by
`__e_acsl_assert(! (__retres != 0) == ! (__gen_e_acsl_at_5 == 0), ...)`.

Regression test `plugins/e-acsl/tests/constructs/iff_labelled_terms.c`: `ensures` with `\old`,
`ensures` with a formal, `assert` with `\at(b->n, Pre)`, called on two inputs so that each
equivalence holds once with both sides true and once with both sides false.

New oracles `constructs/oracle/iff_labelled_terms.0.res.oracle` and
`constructs/oracle/gen_iff_labelled_terms.0.c`. One existing oracle changes:
`memory/oracle/gen_objects.0.c`, whose two `<==>` checks (`ARR: (0 <= k <= 25) <==> \object_pointer(q)`
and `AM: (0 <= k <= 10) <==> \object_pointer(&a.m[k])`) are now translated with each operand and its
`\aligned`/`\object_pointer` guards computed once (46 lines added, 133 removed). `memory/objects.c`
also passes in the `dev` configuration, which executes it. The other test with `<==>`,
`constructs/lazy.i` (integer operands), keeps its oracle, so its equivalences go through the
interlang translation.

## Validation

Built from `3dff90fc70` with the patch in a copy of `framac-master-audit:3dff90f`
(`dune build @install --release`, `dune install`).

| Check | `master` | Patched |
|---|---|---|
| Reproducer, `ensures` with a formal | `Failure: labels pre-analysis was not performed on construct \old(b)` | builds, exit 0 |
| Reproducer, `assert` with `\at` | same failure on `\at(b->n,Pre)` | builds, exit 0 |
| `constructs/iff_labelled_terms.c`, default and `dev` | translation aborts | pass |
| ptests, every suite, default and `dev` configurations (`format`: default only, see below) | all pass | only differences: the new test and `memory/oracle/gen_objects.0.c` (promoted); then all pass |
| `ocp-indent` on `translate_predicates.ml`; `clang-format` 19 on the test | | clean |
| `git diff --check` | | clean except the new oracles (trailing space after `Warning:`, trailing blank line: the ptests output format, as in every existing oracle) |
| `git apply --check` on `3dff90fc70` | | clean |

`format`: on `master` (unpatched) in this image, `format/printf.c` in the `dev` configuration stops
making progress after its 28th check and was killed after 90 minutes, so the `dev` configuration of
`format` was not compared; its default configuration matches the oracles on `master` and with the
patch.

## Workaround

Write the equivalence as two implications: `(p1 ==> p2) && (p2 ==> p1)`.

## Tracker

Not filed at the time of writing (see the filing note at the top). No report in the 202 open issues of the 2026-11-09 export
([`pub-frama-c_work_items_2026-11-09.csv`](./pub-frama-c_work_items_2026-11-09.csv); searched for
`pre-analysis`, `labels pre`, `<==>`, `equiv`).
