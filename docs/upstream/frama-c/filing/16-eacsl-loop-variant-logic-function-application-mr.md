# [e-acsl] typing getters: look up the normalized term

- Source branch: `fix/eacsl-typing-getters-normalize` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `3dff90fc70`. Patch: [`../patches/16-eacsl-loop-variant-logic-function-application.patch`](../patches/16-eacsl-loop-variant-logic-function-application.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #2806.

## Problem

`Logic_normalizer` replaces an application of a logic function whose body reads memory by an
application of a copy specialized for the `Here` label. `Typing.type_term` types and memoizes the
normalized term, but the getters `get_number_ty`, `get_cast` and `get_effective_ty` looked up the
term they were given. Two callers pass the original term, and the translation aborted with
`typing was not performed on construct len3(s)`:

- `Loops.handle_annotations`, when such an application is the whole loop variant
  (`loop variant len3(s);`);
- `Translate_utils.env_of_li`, when such an application is bound by a `\let`
  (`loop variant \let k = len3(s); k;`, or the same `\let` in an `assert`).

## Change

- `plugins/e-acsl/src/analyses/typing.ml`: a helper `get_info` normalizes the term with
  `Logic_normalizer.get_term` before the lookup, as `Interval.get_from_profile` already does, and
  the three getters use it (`get_typ` and `get_effective_typ` go through them). A term that the
  normalizer does not replace is looked up as before.
- New test `plugins/e-acsl/tests/constructs/logic_app_reading_memory.c`, with both loop variants
  (plain application and `\let`) on a correct loop; new oracles
  `constructs/oracle/logic_app_reading_memory.0.res.oracle` and
  `constructs/oracle/gen_logic_app_reading_memory.0.c`. No other oracle changes.

With the change, an `assert \let k = len3(s); k >= 0;` no longer aborts but is ignored with the
existing warning ``E-ACSL construct `function application' is not yet supported``: the
memory-tracking analysis does not handle a function application bound by `\let`. That limitation is
unchanged.

## Testing

On a build of this branch (Debian 13, OCaml 5.5 switch, gcc 14):

- Reproducers of the issue (plain and `\let` variants): the translation aborted before the change;
  after it, both build and the instrumented programs exit with 0. A variant that does not decrease
  (`loop variant len3(t);` with `t` constant) is reported at run time (`Variant failed`).
- `constructs/logic_app_reading_memory.c`: the translation aborts before the change (default and
  `dev` configurations); passes after.
- E-ACSL ptests, every suite, default and `dev` configurations, on this branch and on `master`:
  the only difference is the new test (fails on `master`, passes here). In my environment
  `format/printf.c` hangs in the `dev` configuration on `master` as well (no progress after its
  28th check), so the `format` suite was compared in the default configuration only.
- `git diff --check` reports only the new oracle files (the trailing space after `Warning:` and the
  trailing blank line that ptests writes in every oracle). The patch applies with
  `git apply --check` on `3dff90fc70`.
- `make check-lint` and `make check-headers` were not run (my build tree is not a Git checkout);
  `ocp-indent` on `typing.ml` and `clang-format` 19 (`--dry-run -Werror`, with
  `plugins/e-acsl/.clang-format`) on the new test are clean.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
