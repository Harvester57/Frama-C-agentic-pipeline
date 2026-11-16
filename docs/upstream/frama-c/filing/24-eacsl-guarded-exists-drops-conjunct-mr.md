# [e-acsl] check every conjunct after the guard of a quantification

- Source branch: `fix/eacsl-guarded-quantifier-goal` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `3dff90fc70`. Patch: [`../patches/24-eacsl-guarded-exists-drops-conjunct.patch`](../patches/24-eacsl-guarded-exists-drops-conjunct.patch)

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

The `Pimplies` case discards the goal of its left operand the same way:
`\forall integer n; (0 <= n < size ==> P) ==> Q` is checked as `\forall integer n; 0 <= n < size ==> Q`,
which drops `P` and every `n` outside the range.

## Change

`plugins/e-acsl/src/analyses/bound_variables.ml`, `visit_quantif_relations`:

- `Pand`: when the visit of the left operand returned a goal, the goal is the conjunction of that goal and
  the right operand (`Logic_const.pand`). The goal is stored in the `Quantifier` table, which typing,
  interval inference, label analysis and `Quantif.convert` all read, so they all see the same predicate.
- `Pimplies`: when the left operand already contains the whole guard, the predicate is rejected with
  "invalid quantification guard", like the other unsupported guards. E-ACSL then warns and ignores the
  annotation instead of checking a weaker predicate.

The new test `constructs/quantif_conjunctions.c` asserts true predicates whose translation was wrong
before (`!(\exists ...)` with a false middle conjunct fails at run time without the change), plus the
rejected implication form.

## Testing

All on Debian 13 (gcc 14.2.0), `master` at `3dff90fc70` built with dune, then the same tree with this
patch:

- Reproducer from the issue, built with `e-acsl-gcc -X` and run: before, only `swapped` fails (exit
  134) and the other four runs exit 0. After, the four `\exists` preconditions fail with
  `Precondition failed` (exit 134), and the `\forall` one is rejected at instrumentation time with the
  "invalid quantification guard" warning (so not checked, run exit 0).
- The new test `constructs/quantif_conjunctions.c` fails on unpatched `master` (its line 10,
  `!(\exists ... n == 1000 && n >= 0)`, fails at run time); with the patch it passes in the default
  configuration and in the `dev` configuration (compiled and run). Its oracle records the warning for
  the rejected implication.
- `frama-c-ptests -create-missing-oracles plugins/e-acsl/tests`, then `dune build --release -j 6` on
  `@plugins/e-acsl/tests/ptests_config` (198 results) and on `ptests_config_dev` in every test directory
  except `libc/` and `format/` (188 results). The only differences are the new oracles, which I promoted;
  on the final run every test matches its oracle. No existing oracle changes. Not completed: the `dev`
  configuration of `libc/` and `format/` (their tests abort child processes on purpose, and the crash
  handler of my host made `format/printf.c` exceed a 40-minute timeout); their default configuration
  ran and matches.
- `git diff --check` reports nothing in the source and the test; in the generated oracles it reports
  the trailing space after `Warning:` and the final blank line, as for the existing oracles.
- `ocp-indent` 1.9.0 with the repository's `.ocp-indent`: `bound_variables.ml` unchanged.
- Not run: `make check-lint` and `make check-headers` (my build tree is not a git checkout). The patch
  adds no source file; the new test has no header, like its neighbours.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
