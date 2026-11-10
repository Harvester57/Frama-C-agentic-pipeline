# E-ACSL: `<==>` over a labelled term (`\old`, `\at`, or a formal in a postcondition) aborts with `labels pre-analysis was not performed` (regression in 35)

Draft for the Frama-C tracker (https://git.frama-c.com/pub/frama-c/-/issues). Listed as Issue 14 in
[`frama-c-e-acsl-issues.md`](frama-c-e-acsl-issues.md#issue-14-iff-over-a-labelled-term-aborts-the-translation).

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
`Translate_ats.to_exp` (`translate_ats.ml:504`) raises the fatal error.

In 34 the rewrite reused `p1` and `p2` without copying:

```ocaml
| Piff(p1, p2) ->
  let rewritten = (* (p1 <==> p2) <==> (p1 ==> p2 && p2 ==> p1) *)
    Logic_const.pand ~loc
      (Logic_const.pimplies ~loc (p1, p2),
       Logic_const.pimplies ~loc (p2, p1))
  in
```

35 adds:

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
| `35.0~~dev (Bromine)`, image `framac-analysis:latest` (pipeline image, 2026-11-08) | **fails** |
| `34.0~~dev (Selenium)`, image `framac-pipeline:fc34-20261105` | works |

Debian 13, clang 19 / gcc 14, default `e-acsl-gcc` options. `master` could not be checked: the
tracker's raw-file and history pages refuse automated requests.

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

## Proposed fix (not validated)

Do not translate a predicate that the labels pre-analysis has not seen. Two ways:

1. Translate `p1` and `p2` once and combine the two C expressions, as the interlang `Piff` case
   (`translate_predicates.ml:65`) already does at the expression level: `e1 = to_exp p1`,
   `e2 = to_exp p2`, result `(!e1 || e2) && (!e2 || e1)` (or `!e1 == !e2`). No copies are needed,
   and each operand's RTE guards are generated once.
2. Keep the copies, but give their labelled terms the original terms' entries in
   `at_data_for_pots` (a `Labels` function that maps a copy onto its original), so
   `Labels.at_for_pot` finds them.

Option 1 is the smaller change. We have not built Frama-C with either change, so neither is
validated. The copies were presumably added so the RTE analysis sees each occurrence once, and a fix
must keep that.

## Workaround

Write the equivalence as two implications: `(p1 ==> p2) && (p2 ==> p1)`.

## Tracker

Not filed. No report in the 202 open issues of the 2026-11-09 export
([`pub-frama-c_work_items_2026-11-09.csv`](pub-frama-c_work_items_2026-11-09.csv); searched for
`pre-analysis`, `labels pre`, `<==>`, `equiv`).
