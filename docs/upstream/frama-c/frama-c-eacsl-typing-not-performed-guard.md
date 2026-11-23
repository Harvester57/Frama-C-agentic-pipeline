# E-ACSL: internal error `typing was not performed` on quantifiers with unsupported guards and on binary operations / libc contracts (`stpncpy`, `strlcat`)

Draft for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).
**Not filed.** Issue 54 of this folder, drafted on 2026-11-22. Filing remains paused pending the
maintainers' reply on [#2832](https://git.frama-c.com/pub/frama-c/-/work_items/2832).

**Package:**
[issue text](./filing/54-eacsl-typing-not-performed-guard-issue.md),
[MR text](./filing/54-eacsl-typing-not-performed-guard-mr.md),
[reproducer](./repro/54-eacsl-typing-not-performed-guard.sh) with its
[C file](./repro/54-eacsl-typing-not-performed-guard.c), and
[patch](./patches/54-eacsl-typing-not-performed-guard.patch) (validated on `master` `189053d4a2`).

## Summary

E-ACSL aborts with an internal error (`Failure: typing was not performed on construct 0` or `1`,
exit status 4) whenever an unsupported subterm raises `Error.Not_yet` inside a composite construct in
`Typing` that short-circuits before typing its remaining children:

- **Quantifiers (`Pforall`/`Pexists`):** an unsupported bound (e.g. `undef_fn(x) <= i < 3 ==> i >= 0`
  or `strlen(src)` in Frama-C's `stpncpy` postcondition `dest_nul_padded`) aborts
  `type_bound_variables` before typing `goal`. During translation, `Loops.mk_nested_loops` translates
  `goal` first (or `Translate_ats.for_stmt` pre-translates `\old(dest)`'s `\aligned(dest, 1)` RTE
  guard), crashing on an untyped constant.
- **Binary operations (`TBinOp`) and other composite constructs:** an unsupported first operand
  (e.g. `f(a) + f(b)` where `f` has a `reads` clause, or `strlen(dest) + strlen(src)` in Frama-C's
  `strlcat` postcondition `bounded_result`) aborts `type_term` before typing the second operand.
  `Labels.preprocess` still registers `\old(b)` / `\old(src)` for `Translate_ats.for_stmt`, which
  crashes on the untyped constant `1` in its alignment RTE guard.

## Versions

| | Result |
| :-- | :-- |
| `34.0~beta (Selenium)`, opam build (`framac-analysis:latest`, 2026-11-22) | **aborts (exit 4)** (`Failure: typing was not performed on construct 0` / `1`) |
| `35.0~~dev (Bromine)`, `master` `189053d4a2` (`framac-master-audit:189053d`, 2026-11-22) | **aborts (exit 4)**, identical messages (`RESULT: bug present (4 of 4 cases fail)`) |
| `master` `189053d4a2` + [`./patches/16-eacsl-loop-variant-logic-function-application.patch`](./patches/16-eacsl-loop-variant-logic-function-application.patch) (`!37`) | **still aborts (exit 4)** on `quant`, `stpncpy`, and `strlcat` (distinct from `#2806`/`!37`) |
| `master` `189053d4a2` + [`./patches/54-eacsl-typing-not-performed-guard.patch`](./patches/54-eacsl-typing-not-performed-guard.patch) | **fixed** (`RESULT: fixed`, 4/4 cases exit 0 with `not yet supported` warnings) |

Debian 13 (trixie), OCaml 5.5, gcc 14.2.0.

## Root cause

In `plugins/e-acsl/src/analyses/typing.ml`, some composite constructs (`TUnOp LNot`, `Tapp`,
`Prel`/`Pand`/`Por`/`Pxor`/`Pimplies`/`Piff`) already catch `Error.Not_yet` so all sibling children
are typed before re-raising, because:

1. `Labels.preprocess` visits the whole annotation and registers `\at`/`\old` terms for
   `Translate_ats.for_stmt` regardless of whether an earlier sibling is unsupported;
2. `Loops.mk_nested_loops` translates quantifier goals before translating loop bounds.

All remaining composite cases (`TUnOp (Neg | BNot)`, `TBinOp`, `TCast`, `Tif`, `Trange`, `Tlet`,
`type_bound_variables`, `Papp`, `Pif`, `Plet`, `Pforall`/`Pexists`, `Pseparated`, `Paligned`) still
short-circuited on `Error.Not_yet` / `Error.Typing_error`, either when computing a typing context via
`Interval` or when typing children sequentially.

## Distinctness from `#2806` (`!37`)

Package 16 ([`./patches/16-eacsl-loop-variant-logic-function-application.patch`](./patches/16-eacsl-loop-variant-logic-function-application.patch),
filed as `#2806`/`!37`) normalizes lookup keys in `Typing`'s getters (`get_number_ty`,
`get_effective_ty`). In Stage 1 validation, we applied patch 16 onto `master` `189053d4a2`, rebuilt,
and re-ran the `quant`, `stpncpy`, and `strlcat` reproducers: all three still aborted with exit 4
(`typing was not performed on construct 0` / `1`), because the constants in the skipped sibling
subterms were never entered into `Typing`'s memo table at all.

## Fix and validation

Patch [`./patches/54-eacsl-typing-not-performed-guard.patch`](./patches/54-eacsl-typing-not-performed-guard.patch):
one commit (`f310672f09`) on `master` `189053d4a2`, 4 files (1444 insertions, 79 deletions:
`plugins/e-acsl/src/analyses/typing.ml`, plus regression test
`plugins/e-acsl/tests/constructs/typing_unsupported_sibling.c` and its 2 oracles).

Validated on 2026-11-22 in `framac-master-audit:189053d` (`master`
`189053d4a2bd460c5c557dba8569474ff0419e73`):

- **Patch hygiene:** `git format-patch` produces zero file-mode changes and no executable files.
- **New test against unpatched `master`:** `typing_unsupported_sibling.c` FAILS with exit 4
  (`Failure: typing was not performed on construct 0`).
- **New test against patched sources:** `typing_unsupported_sibling.c` PASSES in both default and
  `dev` configurations.
- **Entire E-ACSL suite, default configuration:** `./dev/test.sh -p plugins/e-acsl` PASSES (exit 0,
  zero diffs on existing oracles).
- **4-way stacking (`04` + `05` + `16` + `54` on `typing.ml`):** `git am --3way --keep-non-patch`
  auto-merges `typing.ml` cleanly with zero conflicts, builds, and passes
  `typing_unsupported_sibling.c`.
- **`./dev/check-files.sh -p HEAD~1`:** PASSES (`Debian clang-format version 19.1.7`,
  `Lint 4 file(s)`).
- **Installed patched tree + reproducer:** `RESULT: fixed` (4/4 cases exit 0; before patch:
  `RESULT: bug present (4 of 4 cases fail)`).

Not run: 32-bit targets and `make default-tests` outside `plugins/e-acsl`.

## Duplicates

Searched live on 2026-11-22 via read-only GitLab API (`pub/frama-c`, issues and merge requests, all
states) for `typing was not performed`, `type_bound_variables`, `stpncpy`, `strlcat`, `do_both`,
and `typing.ml`. Confirmed distinct from `#2806`/`!37` (package 16), `#2795`/`!25` (package 04),
and `#2796`/`!26` (package 05); zero duplicates in `pub/frama-c`, the CSV snapshot, or packages
`01`-`50`.

## For the pipeline

**Recommended for the local `opam/` patch queue:** prevents Frama-C exit-4 internal crashes whenever
a C target calls Frama-C libc `stpncpy` or `strlcat` (or uses quantifiers/expressions with
unsupported subterms) during Phase 1 E-ACSL instrumentation.
