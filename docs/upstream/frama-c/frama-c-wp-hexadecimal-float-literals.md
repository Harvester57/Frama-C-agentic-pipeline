# WP: hexadecimal floating-point literals are not read (a dropped hypothesis, and a wrong proof with `-wp-model +real`)

Draft for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).
**Filed on 2026-11-18** as [#2831](https://git.frama-c.com/pub/frama-c/-/work_items/2831), with
merge request [!59](https://git.frama-c.com/pub/frama-c/-/merge_requests/59). Issue 42 of this
folder.

**Package:**
[issue text](./filing/42-wp-hexadecimal-float-literals-issue.md),
[MR text](./filing/42-wp-hexadecimal-float-literals-mr.md),
[reproducer](./repro/42-wp-hexadecimal-float-literals.sh) with its
[C file](./repro/42-wp-hexadecimal-float-literals.c), and
[patch](./patches/42-wp-hexadecimal-float-literals.patch) (validated on `master` `b80fcac74f`).

## Summary

WP converts a floating-point literal to a rational with `Cfloat.parse_literal`
(`plugins/wp/src/Cfloat.ml`), which reads decimal digits only. Three symptoms, one function:

| Literal | Model | Result on `master` |
| :-- | :-- | :-- |
| Hexadecimal, no suffix: `0x1.8p1`, `DBL_MAX` | both | `Unexpected constant literal`. In a contract: a warning, and the term becomes an unknown value, so the hypothesis is lost (the goal is tagged `Stronger`). In a lemma: `User Error`, WP stops |
| Hexadecimal with a suffix: `0x1.8p1f` | `-wp-model +real` | Read as **0**, no message. `0x1.8p1f == 0.0` is proved by Qed: a wrong proof |
| `f32` or `f64` suffix: `1.5f32`, `0x1.8p1F64` | both | `Unexpected constant literal`, as in the first row |

Who meets it without writing a hexadecimal literal:

- **Users of `<float.h>`:** Frama-C's header defines `FLT_MAX`, `DBL_MAX`, `FLT_MIN`, `DBL_MIN`,
  `FLT_EPSILON`, `DBL_EPSILON` and the `_TRUE_MIN` ones as hexadecimal literals. Each of the six
  tried in a `requires` gives the warning. The `LDBL_*` ones do not, only because their `L` suffix
  takes the other path of the default model.
- **Callers of `exp` and `expf`:** their contracts in `share/libc/math.h` (lines 783 to 835) use
  hexadecimal bounds in `assumes` clauses, so a WP run on a caller prints four warnings.

Origin: a question by Linglong Meng on the public `frama-c-discuss` list (2026-10) about
`requires x+1 <= DBL_MAX` with Frama-C 33.0:
https://groupes.renater.fr/sympa/arc/frama-c-discuss/2026-10/msg00002.html. The issue and MR texts
credit the report and link the thread (added on the owner's request). The archive page sits behind
an anti-harvesting button, so the link was not opened from the filing session: the URL is the one
the owner gave. The report covers the first row of the table only, and its contract has a second,
unrelated problem (`\result == x + 1` is real arithmetic), which the issue leaves out.

## Cause

`parse_literal ~model v r` (lines 138 to 175 on `b80fcac74f`):

1. In the Float model, if `r` matches `.*[fldFLD]$`, return the value `v` computed by the kernel.
2. Otherwise match `[-+]?[0-9]*`, an optional `\.[0-9]*`, an optional `[eE][-+]?[0-9]*`, and
   accept if the end of `r` is reached **or what is left matches `.*[fldFLD]$`**.

- `0x1.8p1`: the digits are `0`, what is left is `x1.8p1`, which does not end with a suffix letter:
  rejected.
- `0x1.8p1f` in the Real model (step 1 does not apply): what is left is `x1.8p1f`, which does end
  with `f`: accepted, with the digits read so far, `0`.
- `1.5f32`: ends with `2`, so step 1 does not apply, and what is left (`f32`) is not accepted.

The same function serves the terms (`acsl_lit`) and, in the Real model, the constants of the code
that still have their source text (`code_lit`), so `return 0x1.8p1f;` is read as `return 0;` under
`-wp-model +real`.

## Versions

| | Result |
|---|---|
| `35.0~~dev (Bromine)`, `master` at `b80fcac74f` (the audit image's tree moved to it and reinstalled) | all three symptoms; the reproducer prints `RESULT: bug present (4 of 4 cases fail)` |
| `35.0~~dev (Bromine)`, `master` at `95408044f7` (image `framac-master-audit:9540804` as built) | the same: the reproducer (the command of its header, as written), the four commands of the issue, and callers of `exp` and `expf`; `Cfloat.ml` is the same file on both commits |
| `34.0~beta (Selenium)` (image `framac-analysis:latest`, Alt-Ergo 2.4.3) | the same, on the same runs; the two logs differ only by the version lines and the timings |
| `33.0` | the version of the mailing-list report (the warning and the `Timeout (Stronger)` are in it); not run here. `parse_literal` (compared with `git show`; the file is `src/plugins/wp/Cfloat.ml` at the tag) and the `DBL_MAX` definition are identical at the tag, and `extract_suffix` is in its kernel. The rest of `Cfloat.ml` differs |
| `master` at `b80fcac74f` with the patch installed | `RESULT: fixed` |

## Reproduction

[`./repro/42-wp-hexadecimal-float-literals.sh`](./repro/42-wp-hexadecimal-float-literals.sh) runs
[`./repro/42-wp-hexadecimal-float-literals.c`](./repro/42-wp-hexadecimal-float-literals.c) four
times, one case per run (`-cpp-extra-args=-DCASE_contract`, `lemma`, `suffix`, `real`), with
`-wp-prover none -wp-print`: Qed decides every goal, so no prover and no cache are needed. The
header of the script holds the output before and after.

## Fix

[`./patches/42-wp-hexadecimal-float-literals.patch`](./patches/42-wp-hexadecimal-float-literals.patch):
one commit on `b80fcac74f`, eight files. The source change is 24 lines added and 4 removed in
`plugins/wp/src/Cfloat.ml`:

- **Suffix:** `parse_literal` removes it with the kernel's `Floating_point.extract_suffix` (in
  the kernel since 33.0, with `f32` and `f64`), and what is left must be read entirely. The
  `.*[fldFLD]$` test is gone, so a literal that is not understood can no longer be cut short.
- **Hexadecimal:** new `parse_hexadecimal`, the exact rational of `[+-]?0x<hex>[.<hex>]p<exponent>`
  (requiring at least one hex digit in the integer or fractional part, since `Z.of_string_base 16`
  otherwise parses empty or sign-only strings as `0`; the digits as an integer, times two to the
  power of the exponent minus four per fractional digit). The optional leading sign `[-+]?` matches
  `re_mantissa` and accepts negative hexadecimal literals emitted by `Logic_const.treal` under
  `-float-print hex` (for instance, assertions generated by `reduc`).
- **Unchanged:** the decimal code, and the rule of the Float model that a suffixed literal denotes
  the value rounded by the kernel. `0.1f32 == 0.1` is not provable there, as `0.1f == 0.1` is not.

New test `plugins/wp/tests/wp_acsl/float_literals.i`, default and `qualif` configurations, three
runs each (Float model, Real model, and `eva` + `reduc` with `-float-print hex`; six oracles):
lemmas and check lemmas covering unsigned and negative hexadecimal literals, `DBL_MAX`, `f`/`d`/`L`/`f32`/`F64`
suffixes, non-exact suffixed literals (`0.1f32` and `0.1F64`, verifying Float-model rounding to
`0x1.99999ap-4` / `0x1.999999999999ap-4` vs Real-model exact `0.1`), a contract with hexadecimal
bounds, a function returning `0x1.8p1f`, and `neg_hex_reduc` exercising negative hexadecimal
literals generated by `reduc` under `-float-print hex`. Every goal is `Prove: true.` by Qed.

### Validation

Run on 2026-11-18 in one container of `framac-master-audit:9540804` whose `master` was
fast-forwarded to `b80fcac74f` (`git ls-remote` just before), rebuilt and reinstalled. The steps
of [`../../../tools/upstream_audit/revalidate.sh`](../../../tools/upstream_audit/revalidate.sh)
`package` were run by hand, because that script runs the `dev` configuration and the E-ACSL suite:

- **Commit:** `bed2bf983f` on the branch `fix/wp-hexadecimal-float-literals`, author and committer
  the GitLab noreply address; six files, no file-mode change and no executable file. The exported
  patch file, applied with `git am --keep-non-patch` on a fresh branch from `master`, gives the
  same tree.
- **New test against `master`'s `Cfloat.ml`:** the default and the `qualif` configurations both
  fail (`float_literals.i:18: User Error: Unexpected constant literal "1.5F64"`, in both models).
  With the patch both pass.
- **`plugins/wp`, default configuration, with the patch:** passes, 427 result logs, the two new
  ones included. No existing oracle changes.
- **`qualif` configuration:** there is no WP cache in the image (`FRAMAC_WP_CACHE=offline`), so a
  test that needs a prover ends with `Missing Test Results`. `wp_acsl/float_const.i`,
  `wp_plugin/float_real.i` and `wp_plugin/float_format.i` fail that way with `master`'s sources
  and with the patch, with the same output; `wp_typed/unit_float.i` and the new test pass. The
  rest of `qualif` was not run.
- **`./dev/check-files.sh -p HEAD~1`:** passes (`Lint 6 file(s)`); `git diff --check` is clean.
  The new test was reformatted once with clang-format before the commit; ocp-indent changed
  nothing.
- **Reproducer:** `RESULT: bug present (4 of 4 cases fail)` with `master`'s sources installed
  and on `34.0~beta`, `RESULT: fixed` with the patch.
- **The commands of the issue text**, before and after, as the MR text reports them.
- **Differential:** about fifty probes (one literal per lemma in both models, the `<float.h>`
  macros, a caller of libc math functions, the corrected contracts of the original question) were
  run with `master`'s sources and with the patch. Every line that differs involves a hexadecimal
  literal or an `f32`/`f64` suffix. The decimal literals (`1.5e1`, `1.5e1f`, `1e+2`, `1.`, `.5`,
  `0.1f == 0.1`) and the suffixed hexadecimal ones in the Float model are unchanged.
- **With provers** (Alt-Ergo 2.6.4): `requires \is_finite(x); requires x + 1 <= DBL_MAX;` with
  `ensures \result == (double)(x + 1);` on `return x + 1.0;` goes from 5 of 6 goals (one
  `Timeout (Stronger)`) to 6 of 6 under `-wp-rte`. On a caller of `exp`,
  `call_exp_requires_not_overflow_argument` goes from `Timeout (Stronger)` to `Valid` (6 of 8 to
  7 of 8; `assigns_normal_part1` times out before and after, without the `Stronger` tag after).
- **`expf`:** a caller gives four warnings (`0x1.62e42ep+6`, `0x1.9fe368p6`) and 6 of 8 before
  the patch; no warning and 7 of 8 after, as for `exp`. The "after" run was made at filing time,
  on the branch rebuilt from the patch file (same tree, `27772c3d1c`), where the reproducer also
  printed `RESULT: fixed`.
- **`real.c` of the issue with a prover, after the patch:** 3 of 4. The lemma is `Unknown`, and
  Alt-Ergo closes the postcondition `\result == 0.0` because WP gives it the unproved lemma
  `three_is_zero` as a hypothesis. With `-wp-prover none -wp-print` both goals are `Prove: false.`,
  which is why the issue and the reproducer use that form.

Not run: the tests of the other plugins and of the kernel, the WP `ce` configuration, and
`make default-tests` as a whole. The scripts and logs of these runs were in the session's scratch
directory, not in the repository, and the container was removed afterwards.

### Post-filing patch update (leading sign + non-exact suffixed & `-float-print hex` tests)

Updated the local patch (`109d417cd6` on `b80fcac74f`, 8 files, single commit, zero mode changes)
and revalidated in a fresh `framac-master-audit:b80fcac` container with `JOBS=4 /w/revalidate.sh package 42`:

- `git am --keep-non-patch`: exit 0 (no mode changes, no executable files).
- `A0` build with `master` sources: exit 0; `A1` default `wp_acsl/float_literals.i` on `master`
  sources: exit 1 (all three runs fail with `Unexpected constant literal`); `A2` `dev`: exit 0
  (no `dev` config for WP tests).
- `B0` build with patched sources: exit 0; `B1` default `wp_acsl/float_literals.i`: exit 0;
  `B2` `dev`: exit 0; `qualif` `wp_acsl/float_literals.i` (all three runs): exit 0.
- `C1` default `plugins/e-acsl`: exit 0; `C2` default `plugins/wp/tests/wp_acsl`: exit 0;
  full `plugins/wp` default suite: exit 0.
- `D` `./dev/check-files.sh -p HEAD~1`: exit 0 (`Lint 8 file(s)`).
- `E0` install + `reproducer 42 (after)`: exit 0 (`RESULT: fixed`).
- OCaml edge-case verification of `parse_hexadecimal`: `"-0x1.8p1"` -> `-3`, `"+0x1.8p1"` -> `3`,
  `"-0x.8p0"` -> `-1/2`, `"-0x0p0"` -> `0`, while empty-digit forms (`"0xp0"`, `"-0xp0"`,
  `"+0xp0"`, `"0x.p0"`, `"-0x.p0"`, `"+0x.p0"`) raise `Not_found` (preventing `Z.of_string_base 16`
  from silently reading `""`/`"-"`/`"+"` as `0`).

## Filing

**Filed on 2026-11-18**, from the account Harvester57, on the owner's go-ahead ("check expf now
and then fill the issue and merge request"), with the steps of the "Filing" section of
[`./frama-c-libc-ioctl-modem-bits.md`](./frama-c-libc-ioctl-modem-bits.md) (41):

- Upstream `master` was still `b80fcac74f` (`git ls-remote`) just before. The tracker was searched
  again (`Unexpected constant literal`, `hexadecimal float`, `DBL_MAX`): nothing.
- In a container of the audit image with `master` fast-forwarded,
  `make_branches.sh "42 fix/wp-hexadecimal-float-literals"` built the branch from the patch file:
  commit `e49fe7c9f2` (`git am` gives a new id, the committer date changes), tree `27772c3d1c`,
  the one of `bed2bf983f`. That tree was built and installed for the `expf` run above.
- The branch was pushed to the fork from the bundle, through a scratch bare clone
  (`git clone --bare --shared` of the local checkout, plus a fetch of upstream `master`).
- `file_upstream.py issue 42` created #2831, `subst` wrote the number into the MR text, and
  `mr 42` created !59. Title and description of both were read back and are identical to the
  texts.
- !59: one commit, six files, mergeable without conflict, source branch removed on merge,
  maintainers may push, no squash. No label, assignee or reviewer. The CONTRIBUTING and CLA
  checkboxes are left for the owner to tick.
- Both stored descriptions were rendered through GitLab's markdown endpoint: no user mention, no
  strikethrough, every code block closed. The links are #2831, the commit `b80fcac74f`, the
  CONTRIBUTING and CLA pages, and the mailing-list message.

## Not covered

- **`NAN` and `INFINITY` in a term:** WP answers `Builtin \NaN not defined` (and
  `\plus_infinity`), before and after the patch. A different limitation.
- **`INFINITY` in the code under `-wp-model +real`** (seen after the filing, on 2026-11-18):
  `float x = INFINITY;` with `<math.h>` gives `Warning: Unexpected constant literal "INFINITY"`,
  from the same function. The kernel stores the constant with the text `INFINITY`; from a reading
  of the patch it does not handle that text. Run on `master` `b80fcac74f` without the patch only,
  so the result with the patch is not known; candidate H19 of
  [`./frama-c-hunt-2026-11-18-candidates.md`](./frama-c-hunt-2026-11-18-candidates.md). A second
  review judged it not a bug: nothing false is proved (the checks become unknown), and the WP
  manual calls the Real model "completely unsound with respect to C and IEEE semantics".
- **`long double`:** `LDBL_MAX` in code stops WP with `128-bits floats` not implemented, before and
  after.
- **Very large exponents** (`0x1p999999999`, `1e999999999`): the exact rational is built in memory.
  The decimal code already did this; the patch does the same for hexadecimal literals.

## Duplicates

Searched live on 2026-11-18 through the read-only API (`glab api`, issues and merge requests of
`pub/frama-c`, all states; `TIOCMGET` returned #2830 as a control):

- `Unexpected constant literal`, `DBL_MAX`, `float.h`, `hex float`, `Cfloat`: nothing.
- `hexadecimal`: #507 (closed in 2021; a 2016 report, `assert 1.0 < 0x1.0p2047;` crashed with
  `Unrecognized constant "inf"`), #858 and #1754, all unrelated to this parser.
- `literal`, `constant literal`: string-literal and E-ACSL items only.
- In the sources: the message exists only in `Cfloat.ml`; no WP test source has a hexadecimal
  floating-point literal; the WP manual and the Changelog do not mention the limitation.

## For the pipeline

A WP contract written by a prover subagent that bounds a `double` with `DBL_MAX` or `FLT_MAX` loses
that bound on Frama-C 34.0 and earlier, with a warning that is easy to miss. Until a release
carries the fix, write the bound as `\is_finite((double)(e))` or as a decimal literal.
