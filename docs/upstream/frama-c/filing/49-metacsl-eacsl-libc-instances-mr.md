# [meta] warn on calls to functions without specification in reading/writing contexts

- Source branch: `feature/no-footprint-warning` on the fork of `pub/meta`; target branch `master`.
- Based on: `4f43801390`. Patch: [`../patches/49-metacsl-eacsl-libc-instances.patch`](../patches/49-metacsl-eacsl-libc-instances.patch)

<!-- Everything below this line is the merge request description. pub/meta has no merge request template, so there are no checkboxes. -->

Related to #<issue>: this covers the first point of its proposal; the other two stay open.

## Problem

A call to an undefined function is checked through the callee's `assigns` (`\writing`) or `\from`
(`\reading`) clauses. When the callee has a behavior without `assigns`, `inspect_contract` warns
`Cannot analyze footprint of function f: no assigns clause. Assuming meta-properties with
reading/writing contexts are valid in this function.` A function declared without any
specification has no behavior at all, so `Annotations.iter_behaviors` calls nothing and the call
is skipped without a message.

That is the case of every libc function when the code is parsed with the system headers
(`-no-frama-c-stdlib`, which `e-acsl-gcc` uses by default): `memcpy(&protected, ...)` gets no
instance of a `\writing` property and nothing says so.

## Change

- `meta_annotate.ml`, `inspect_contract`: records whether a behavior was seen and, if none was,
  gives the same warning as for a behavior without `assigns`.
- `meta_options.ml` / `.mli`: new warning category `no-footprint` (default status: warning), used
  by both warnings, so that `-meta-warn-key no-footprint=inactive` hides them and
  `no-footprint=error` makes them fatal. The existing warning is therefore printed as
  `[meta:no-footprint] Warning:` instead of `[meta] Warning:`; no existing oracle contains it.
- `README.md` (`\writing` context) and `CHANGELOG.md`: one sentence each.
- New test `tests/meta/no_footprint.i`, with oracles for the default and the `fold`
  configurations: a callee without specification, one with a behavior without `assigns`, one with
  a footprint; run with the default warning status and with `no-footprint=inactive`.

The new warning is given at each call site, as the existing one is. In code parsed with the system
headers, every call from a target to a libc function in a `\writing` or `\reading` property now
warns; that is the point, and `-meta-warn-key no-footprint=inactive` turns it off.

## Testing

In the Docker image of the issue (Frama-C 34.0~beta, OCaml 5.5), MetAcsl `master` `4f43801390`
with the patch, built with `dune build @install` and installed in a throwaway container. The build
needs one line of `meta_parse.ml` removed (the `PLpointer_comparable` case, which the 34.0~beta
kernel does not have); that line is not part of the patch.

- **Reproducer from the issue:** `frama-c -machdep gcc_x86_64 -no-frama-c-stdlib copy.c -meta
  -then-last -print` now prints `[meta:no-footprint] Warning:` `Cannot analyze footprint of function
  memcpy: ...`; with the Frama-C libc the output is unchanged (no warning, the instance is there).
  The E-ACSL runs of the issue are unchanged.
- **New test:** its oracles were generated with the command line of the test (`frama-c -check
  -no-autoload-plugins -load-plugin=metacsl,wp,rtegen,eva,scope,inout no_footprint.i -meta
  [-meta-fold] ... -then-last -print`). Without the change in `meta_annotate.ml` and
  `meta_options.ml` the outputs differ: no warning for `copy`, `touch`'s warning without the
  category, and `Unknown warning key no-footprint` for the second run.
- **Existing tests:** `make tests` does not run in this image (dune stops on documentation files
  of the Frama-C package that the image does not ship). Instead, each `OPT` line of the 19
  existing files of `tests/meta` (21 runs, macros expanded as in the default configuration, not
  the `fold` one) was run with the installed MetAcsl 0.12~beta and with the patched one: every run
  printed its program, and the outputs are identical. The same was done for the `OPT` lines of
  `tests/meta-wp` and `tests/meta-deduce` (15 runs, comparing the `[meta]` lines only, since WP's
  output depends on timing): identical, and no `no-footprint` warning. No oracle of the
  repository other than the new test's contains `Cannot analyze footprint`.
- **Not run:** `make tests` itself, the `fold` configuration of the existing tests, `ocp-indent`,
  and MetAcsl's CI.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
