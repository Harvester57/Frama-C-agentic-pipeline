# [meta] warn on calls to functions without specification in reading/writing contexts

- Source branch: `feature/no-footprint-warning` on the fork of `pub/meta`; target branch `master`.
- Based on: `4f43801390`. Patch: [`../patches/49-metacsl-eacsl-libc-instances.patch`](../patches/49-metacsl-eacsl-libc-instances.patch)

<!-- Everything below this line is the merge request description. pub/meta has no merge request template, so there are no checkboxes. -->

Related to #<issue>: this covers the first point of its proposal; the other two stay open.

## Problem

A call to an undefined function is checked through the callee's `assigns` (`\writing`) or `\from`
(`\reading`) clauses. When the callee has a behavior without `assigns`, `inspect_contract` warns
`Cannot analyze footprint of function f: no assigns clause. Assuming meta-properties with
reading/writing contexts are valid in this function.` When an `assigns` clause lacks `\from`,
`reading_visitor#passthrough_from` warns `Cannot fully analyze read footprint of function f: no
\from part in some assigns clauses.` Neither warning carried a warning category or the call-site
location. Moreover, a function declared without any specification has no behavior at all, so
`Annotations.iter_behaviors` calls nothing and the call is skipped without a message.

That is the case of every libc function when the code is parsed with the system headers
(`-no-frama-c-stdlib`, which `e-acsl-gcc` uses by default): `memcpy(&protected, ...)` gets no
instance of a `\writing` property and nothing says so.

## Change

- `meta_options.ml` / `.mli`: new warning category `no-footprint` (default status: warning), so
  that `-meta-warn-key no-footprint=inactive` silences missing-footprint warnings, `=once` limits
  them globally, and `=error` makes them fatal.
- `meta_annotate.ml`, `inspect_contract`: records whether a behavior was seen and, if none was,
  emits the same warning as for `WritesAny`, using `~wkey:Meta_options.no_footprint_wkey`,
  `~loc:(Cil_datatype.Stmt.loc stmt)` (matching the `Indirect call` warnings), and `~once:true`
  (deduplicating per call site when both reading and writing properties visit the same call or
  multiple behaviors have `WritesAny`).
- `meta_annotate.ml`, `reading_visitor#passthrough_from`: adds
  `~wkey:Meta_options.no_footprint_wkey` and `~loc:(Cil_datatype.Stmt.loc stmt)` to the existing
  `FromAny` warning (keeping `~once:true` so multiple `FromAny` clauses at the same call site warn
  once, while distinct call sites each report their own file and line).
- `README.md` (`\writing` and `\reading` contexts) and `CHANGELOG.md`: document `no-footprint` and
  the call-site location.
- New test `tests/meta/no_footprint.i`, with all four oracles (`oracle/` and `oracle_fold/`, `.0`
  default and `.1` `-meta-warn-key no-footprint=inactive`), covering both `\writing` (`f_write`)
  and `\reading` (`f_read`) across four callees: unspecified (`copy`), behavior without `assigns`
  (`touch`), `assigns *p;` without `\from` (`assign_only`), and fully specified (`copy_spec`).

All three missing-footprint warnings are now printed as `[meta:no-footprint] <file>:<line>:
Warning:`; no existing oracle in the repository contains `footprint`. In code parsed with the
system headers, every call from a target to a libc function in a `\writing` or `\reading` property
now warns at its call site; that is the point, and `-meta-warn-key no-footprint=inactive` turns it
off.

## Testing

In the Docker image of the issue (Frama-C 34.0~beta, OCaml 5.5), MetAcsl `master` `4f43801390`
with the patch, built with `dune build @install` and installed in a throwaway container. The build
needs one line of `meta_parse.ml` removed (the `PLpointer_comparable` case, which the 34.0~beta
kernel does not have); that line is not part of the patch.

- **Reproducer from the issue:** `frama-c -machdep gcc_x86_64 -no-frama-c-stdlib copy.c -meta
  -then-last -print` now prints `[meta:no-footprint] copy.c:29: Warning:` `Cannot analyze footprint
  of function memcpy: ...`; with the Frama-C libc the output is unchanged (no warning, the instance
  is there). All nine E-ACSL runs of the issue are unchanged.
- **New test (`tests/meta/no_footprint.i`):** all four oracles (`oracle/` and `oracle_fold/`, `.0`
  and `.1`) were generated with the exact `frama-c-ptests` command lines (`frama-c -check
  -no-autoload-plugins -load-plugin=metacsl,wp,rtegen,eva,scope,inout no_footprint.i -meta
  [-meta-fold] [-meta-warn-key no-footprint=inactive] -then-last -print`). Without the patch, all
  four runs differ: `copy` gets no warning in either context, `touch` and `assign_only` lack the
  `no-footprint` category and call-site line, and `.1` warns `Unknown warning key no-footprint`
  while still printing the warnings. Extra checks with the patch: `-meta-warn-key
  no-footprint=error` exits 1 with `User Error` on all five call sites; `=once` emits only the
  first warning globally; a callee with `assigns a, b;` called at two lines warns once per call
  site with its own line number.
- **Existing tests (default and `fold` configurations):** `dune build @ptests` does not run in this
  image (it checks Frama-C doc/man files stripped from the image), so `frama-c-ptests tests` was run
  to generate the exact dune commands for every suite and configuration, and all 72 existing runs
  were executed with installed MetAcsl 0.12~beta and with the patched build:
  - `tests/meta`: 21 default + 21 `fold` runs — full stdout/stderr identical between before and
    after, and byte-for-byte identical to the committed `oracle/` and `oracle_fold/` files; zero
    `no-footprint` warnings.
  - `tests/meta-wp`: 12 default + 12 `fold` runs — exit codes, `[meta]`/`[meta:*]` lines, and
    non-timing output identical between before and after; zero `no-footprint` warnings.
  - `tests/meta-deduce`: 3 default + 3 `fold` runs — exit codes and `[meta]`/`[meta:*]` lines
    identical (SWI-Prolog is not installed in the image).
- **Not run:** `dune build @ptests` directly, SWI-Prolog deduction checks, `ocp-indent`, and
  MetAcsl's CI.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
