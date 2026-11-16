# [e-acsl] translate both operands of <==> once, without copies

- Source branch: `fix/eacsl-iff-labels` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `3dff90fc70`. Patch: [`../patches/14-eacsl-iff-labelled-term.patch`](../patches/14-eacsl-iff-labelled-term.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #2800.

## Problem

Since a9a91e590f, the translation of `p1 <==> p2` outside interlang rewrites the predicate as
`(p1 ==> p2) && (p2' ==> p1')`, where `p1'` and `p2'` are deep copies, so that the RTE analysis
sees the second occurrence of each operand. The labels pre-analysis runs once on the whole file and
records labelled terms by identity, so it knows nothing about the copies. When an operand contains
`\old`, `\at`, or a formal in a postcondition, the translation aborts with
`labels pre-analysis was not performed on construct \old(b)`.

## Change

- `plugins/e-acsl/src/code_generator/translate_predicates.ml`, case `Piff` of
  `predicate_content_to_exp_old`: translate `p1` and then `p2` once each and return `!e1 == !e2`,
  as the interlang translation of `Piff` already does with its operands. In the former rewriting
  both operands were always evaluated (`p1` in the first conjunct; `p2` in the first conjunct, or in
  the second one when `p1` is false), so evaluating each once, unconditionally, keeps the semantics
  and the RTE guards of each operand, which are now generated once, before the comparison. No copy
  is needed.
- New test `plugins/e-acsl/tests/constructs/iff_labelled_terms.c`: two postconditions (`\old`, and a
  formal) and an assertion (`\at(..., Pre)`) with `<==>`, called with values that make the
  equivalences true on both sides; new oracles `constructs/oracle/iff_labelled_terms.0.res.oracle`
  and `constructs/oracle/gen_iff_labelled_terms.0.c`.
- `memory/oracle/gen_objects.0.c`: the two `<==>` checks of `memory/objects.c` (`ARR` and `AM`)
  are translated the new way. Each operand, with its `\aligned` and `\object_pointer` guards, is
  computed once before the comparison, instead of twice in two nested implications. No other
  oracle changes: the oracle of the other test with `<==>`, `constructs/lazy.i` (integer operands
  only), is unchanged, so its equivalences go through the interlang translation.

## Testing

On a build of this branch (Debian 13, OCaml 5.5 switch, gcc 14):

- Reproducers of the issue (`ensures` with a formal, `assert` with `\at`): the translation aborted
  before the change; after it, both build and the instrumented programs exit with 0.
- `constructs/iff_labelled_terms.c`: the translation aborts before the change (default and `dev`
  configurations); passes after.
- E-ACSL ptests, every suite, default and `dev` configurations, on this branch and on `master`:
  the only differences are the new test (fails on `master`, passes here) and
  `memory/oracle/gen_objects.0.c`. `memory/objects.c` also passes in the `dev` configuration, which
  runs it. In my environment `format/printf.c` hangs in the `dev` configuration on `master` as well
  (no progress after its 28th check), so the `format` suite was compared in the default
  configuration only.
- `git diff --check` reports only the new oracle files (the trailing space after `Warning:` and the
  trailing blank line that ptests writes in every oracle). The patch applies with
  `git apply --check` on `3dff90fc70`.
- `make check-lint` and `make check-headers` were not run (my build tree is not a Git checkout);
  `ocp-indent` on `translate_predicates.ml` and `clang-format` 19 (`--dry-run -Werror`, with
  `plugins/e-acsl/.clang-format`) on the new test are clean.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
