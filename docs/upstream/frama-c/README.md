# Upstream Frama-C & E-ACSL Bug Reports

- **Upstream Directory Index:** [`../README.md`](../README.md)
- **Master Issue Catalog & Validation History:** [`./frama-c-e-acsl-issues.md`](./frama-c-e-acsl-issues.md)

This folder holds everything needed to report the Frama-C bugs the pipeline found to
[`pub/frama-c`](https://git.frama-c.com/pub/frama-c/-/issues): one long analysis draft per bug, and a
**filing package** per bug:

- [`./filing/`](./filing/README.md): paste-ready GitLab issue and merge-request texts;
- [`./repro/`](./repro/README.md): standalone reproducers;
- [`./patches/`](./patches/README.md): `git format-patch` files.

The snapshot `./pub-frama-c_work_items_2026-11-09.csv` lists the 202 upstream items that were open
on 2026-11-09. It predates Issues 15 to 31, so do not rely on it alone for deduplication.

---

## Status (2026-11-15)

- **Filed:** Issue 24 as [#2793](https://git.frama-c.com/pub/frama-c/-/work_items/2793)
  (2026-11-15, account Harvester57), with its fix as merge request
  [!25](https://git.frama-c.com/pub/frama-c/-/merge_requests/25) from the fork `Harvester57/frama-c`
  (private, as GitLab created it), branch `fix/eacsl-guarded-quantifier-goal`, commit `ffccf6f0d7`
  authored with the GitLab noreply address. The CONTRIBUTING and CLA checkboxes of the MR template
  are left for the owner to tick.
- **Filed:** Issue 27 as [#2794](https://git.frama-c.com/pub/frama-c/-/work_items/2794) and Issue 23
  as [#2795](https://git.frama-c.com/pub/frama-c/-/work_items/2795) (2026-11-15). #2794 first went
  up with "reported separately" in place of the link to 23; its description was edited to cite #2795
  once 23 was filed. Their shared fix is merge request
  [!26](https://git.frama-c.com/pub/frama-c/-/merge_requests/26) (branch
  `fix/eacsl-readonly-global-address`, commit `e3e37e8966`, same author and checkboxes as !25),
  which closes both.
- **Filed (batch 1, 2026-11-15):** 03, 13, 04, 04b, 14, 08, 18, 17, 21, 05 and 16, as issues
  #2796–#2806 with merge requests !27–!37, one per issue, in that order (numbers in the table
  below). Same fork, author and checkboxes as !25. After filing, #2797 (13), #2801 (08) and !32 (08)
  were edited to cite each other, and the `#<issue>` placeholders in the filing texts now hold the
  real numbers.
- **Filed (batch 2, 2026-11-15):** 01, 09, 12, 10, 19, 20, 25 and 26, as issues #2807–#2814 with
  merge requests !38–!45, in that order. 10's branch is stacked on 12's, so !41 also shows 12's
  commit, and its description says it depends on !40.
- **Filed:** 15 as [#2815](https://git.frama-c.com/pub/frama-c/-/work_items/2815) (2026-11-15), issue only.
- **Filed:** 22 as [#2816](https://git.frama-c.com/pub/frama-c/-/work_items/2816) (2026-11-15),
  issue only. It lists three possible fixes (the validated patch, a separate table, keeping the RTL
  declaration) and asks the maintainers to choose; the MR text and patch wait for their answer.
- Every package up to 27 is filed. Each further issue or merge request needs the owner's go-ahead.
- **Ready, not filed (2026-11-16):** 28, 29, 30 and 31, found during the c-ares run-1 supervision.
  `master` was still `3dff90fc70` on 2026-11-16 (`git ls-remote`). Each has a full package (issue,
  MR text, reproducer, patch). All four bugs reproduce on `master` and `34.0~beta`.
  - Each patch applies alone on `3dff90fc70` (`git am --keep-non-patch`) and after the 22 earlier
    patches (`git am --3way`). 30 and 31 also apply together in either order. Each was built in
    `framac-master-audit:3dff90f`, and its reproducer was rerun before and after; the patched builds
    are kept as images `framac-master-audit:3dff90f-p28` to `-p31`. The new test of each fails on
    `master` and passes with the patch, and `./dev/check-files.sh -p HEAD~1` passes.
  - **Overlaps with open MRs:** 28 changes `injector.ml` and two concurrency oracles that !28 (13)
    also changes, and 28 changes how !33 (18) registers `"PATH"`; the tests of 30 and 31 include
    `utils/signalled.h`, whose formals !28 instruments. Whichever lands second regenerates those
    oracles; each MR text says so.
  - **Not run:** 28: `format/` `dev` stopped at 1,003 s (no difference so far; master as slow).
    30 and 31: `sprintf.c` in `dev`, `printf.c` in `dev` with both patches together, and 32-bit
    targets (no 32-bit libc in the images).
  - 30's issue asks the maintainers about `int` against `unsigned int` (strict C11 7.21.6.1p9 or
    the 7.16.1.1p2 rule); its MR only accepts promoted unsigned small types, so upstream's
    `printf.c` expectations do not change.
- **Base:** every package was checked against upstream `master` at `3dff90fc70` (2026-11-13), built
  from source in Docker, and against the `34.0~beta (Selenium)` release. All 24 bugs reproduce on
  both.
- **Patches:** 22 of them are validated: each was built and its reproducer run before (bug shows)
  and after (bug gone). The ptests of the touched suites were run. Each MR's "Testing" section lists
  exactly what ran.
- **Applying:** each applies with `git am --keep-non-patch` on its own branch from pristine
  `3dff90fc70`, except 10, which goes on top of 12. All 22 also apply in sequence with `git am --3way`;
  the only overlap is the E-ACSL `Changelog`, which upstream merges with `merge=union`.
- **Regression tests:** every patch adds one, with three exceptions:
  - 10 has none (the E-ACSL suite compiles with gcc);
  - 03's test is the 4 updated `tests/variadic/known` oracles;
  - 16's new test was not confirmed by name to fail on `master` (its reproducer was).
- **ptests not run:**
  - the E-ACSL `dev` configuration of `libc/` for 21, 22, 24 and 27;
  - the `format/` `dev` configuration, which seemed to hang on unpatched `master` too. It does not
    hang: every expected abort paid the WSL2 crash-dump pipe. With `ulimit -c 1` before
    `dune build`, `printf.c` alone finishes in 12-14 minutes (2026-11-16, packages 30 and 31);
  - the WP qualif and counter-example configurations for 19.
- **No patch:** 15 needs a design choice from the maintainers; its issue text lists three options.
  23 has the same root cause as 27, and patch 27 fixes both.
- **Duplicates:** the tracker was searched live on 2026-11-15 (issues and MRs, all states,
  authenticated read-only API) for every bug, and none was found.
  - #2752 and #2787 (WP counter-examples) are related to 19 but distinct; its issue text says why.
  - #197 is a different bug from 22.
  - #177 is the closed issue that 13 shows failing again.

## Coverage

All paths below are relative to this folder.

- **Draft:** the long analysis.
- **Repro:** `repro/<NN>-<slug>.sh` plus its `.c` files.
- **Patch:** `patches/<NN>-<slug>.patch`. "Validated" means built, and the reproducer run before and
  after on `master` `3dff90fc70`.

| # | Component | Bug | Draft | Issue | MR | Repro | Patch |
| :-- | :-- | :-- | :-- | :-- | :-- | :-- | :-- |
| 01 | e-acsl-gcc | Option arguments read again as options | [draft](./frama-c-eacsl-gcc-option-arguments-reparsed.md) | [issue](./filing/01-eacsl-gcc-option-arguments-reparsed-issue.md), filed [#2807](https://git.frama-c.com/pub/frama-c/-/work_items/2807) | [MR](./filing/01-eacsl-gcc-option-arguments-reparsed-mr.md), opened [!38](https://git.frama-c.com/pub/frama-c/-/merge_requests/38) | [sh](./repro/01-eacsl-gcc-option-arguments-reparsed.sh) | [validated](./patches/01-eacsl-gcc-option-arguments-reparsed.patch) |
| 03 | Kernel (Variadic) | Fallback name printed in local initializers | [draft](./frama-c-variadic-fallback-local-init.md) | [issue](./filing/03-variadic-fallback-local-init-issue.md), filed [#2796](https://git.frama-c.com/pub/frama-c/-/work_items/2796) | [MR](./filing/03-variadic-fallback-local-init-mr.md), opened [!27](https://git.frama-c.com/pub/frama-c/-/merge_requests/27) | [sh](./repro/03-variadic-fallback-local-init.sh) | [validated](./patches/03-variadic-fallback-local-init.patch) |
| 04 | E-ACSL | Unbounded range aborts the instrumentation | [draft](./frama-c-eacsl-unbounded-range-abort.md) | [issue](./filing/04-eacsl-unbounded-range-abort-issue.md), filed [#2798](https://git.frama-c.com/pub/frama-c/-/work_items/2798) | [MR](./filing/04-eacsl-unbounded-range-abort-mr.md), opened [!29](https://git.frama-c.com/pub/frama-c/-/merge_requests/29) | [sh](./repro/04-eacsl-unbounded-range-abort.sh) | [validated](./patches/04-eacsl-unbounded-range-abort.patch) |
| 04b | Libc | `getsockopt` precondition unsatisfiable | [draft](./frama-c-getsockopt-unbounded-range.md) | [issue](./filing/04b-libc-getsockopt-unbounded-range-issue.md), filed [#2799](https://git.frama-c.com/pub/frama-c/-/work_items/2799) | [MR](./filing/04b-libc-getsockopt-unbounded-range-mr.md), opened [!30](https://git.frama-c.com/pub/frama-c/-/merge_requests/30) | [sh](./repro/04b-libc-getsockopt-unbounded-range.sh) | [validated](./patches/04b-libc-getsockopt-unbounded-range.patch) |
| 05 | E-ACSL | `sizeof`/alignof of an incomplete type | [draft](./frama-c-eacsl-incomplete-type-sizeof.md) | [issue](./filing/05-eacsl-incomplete-type-sizeof-issue.md), filed [#2805](https://git.frama-c.com/pub/frama-c/-/work_items/2805) | [MR](./filing/05-eacsl-incomplete-type-sizeof-mr.md), opened [!36](https://git.frama-c.com/pub/frama-c/-/merge_requests/36) | [sh](./repro/05-eacsl-incomplete-type-sizeof.sh) | [validated](./patches/05-eacsl-incomplete-type-sizeof.patch) |
| 08 | E-ACSL | False `\initialized(&\result.f)` | [draft](./frama-c-eacsl-struct-result-initialized.md) | [issue](./filing/08-eacsl-struct-result-initialized-issue.md), filed [#2801](https://git.frama-c.com/pub/frama-c/-/work_items/2801) | [MR](./filing/08-eacsl-struct-result-initialized-mr.md), opened [!32](https://git.frama-c.com/pub/frama-c/-/merge_requests/32) | [sh](./repro/08-eacsl-struct-result-initialized.sh) | [validated](./patches/08-eacsl-struct-result-initialized.patch) |
| 09 | E-ACSL | `-e-acsl-assert-print-data` aliases the wrong option | [draft](./frama-c-eacsl-assert-print-data-alias.md) | [issue](./filing/09-eacsl-assert-print-data-alias-issue.md), filed [#2808](https://git.frama-c.com/pub/frama-c/-/work_items/2808) | [MR](./filing/09-eacsl-assert-print-data-alias-mr.md), opened [!39](https://git.frama-c.com/pub/frama-c/-/merge_requests/39) | [sh](./repro/09-eacsl-assert-print-data-alias.sh) | [validated](./patches/09-eacsl-assert-print-data-alias.patch) |
| 10 | e-acsl-gcc | `-G clang` overwrites CFLAGS | [draft](./frama-c-eacsl-gcc-clang-cflags.md) | [issue](./filing/10-eacsl-gcc-clang-cflags-issue.md), filed [#2810](https://git.frama-c.com/pub/frama-c/-/work_items/2810) | [MR](./filing/10-eacsl-gcc-clang-cflags-mr.md), opened [!41](https://git.frama-c.com/pub/frama-c/-/merge_requests/41) | [sh](./repro/10-eacsl-gcc-clang-cflags.sh) | [validated, on top of 12](./patches/10-eacsl-gcc-clang-cflags.patch) |
| 12 | e-acsl-gcc | Compiles without `-D_DEFAULT_SOURCE` | [draft](./frama-c-eacsl-gcc-default-source.md) | [issue](./filing/12-eacsl-gcc-default-source-issue.md), filed [#2809](https://git.frama-c.com/pub/frama-c/-/work_items/2809) | [MR](./filing/12-eacsl-gcc-default-source-mr.md), opened [!40](https://git.frama-c.com/pub/frama-c/-/merge_requests/40) | [sh](./repro/12-eacsl-gcc-default-source.sh) | [validated](./patches/12-eacsl-gcc-default-source.patch) |
| 13 | E-ACSL | Formals never marked initialized (#177 again) | [draft](./frama-c-eacsl-formal-params-initialized.md) | [issue](./filing/13-eacsl-formal-params-initialized-issue.md), filed [#2797](https://git.frama-c.com/pub/frama-c/-/work_items/2797) | [MR](./filing/13-eacsl-formal-params-initialized-mr.md), opened [!28](https://git.frama-c.com/pub/frama-c/-/merge_requests/28) | [sh](./repro/13-eacsl-formal-params-initialized.sh) | [validated](./patches/13-eacsl-formal-params-initialized.patch) (57 oracles) |
| 14 | E-ACSL | `<==>` over a labelled term aborts | [draft](./frama-c-eacsl-iff-labelled-term.md) | [issue](./filing/14-eacsl-iff-labelled-term-issue.md), filed [#2800](https://git.frama-c.com/pub/frama-c/-/work_items/2800) | [MR](./filing/14-eacsl-iff-labelled-term-mr.md), opened [!31](https://git.frama-c.com/pub/frama-c/-/merge_requests/31) | [sh](./repro/14-eacsl-iff-labelled-term.sh) | [validated](./patches/14-eacsl-iff-labelled-term.patch) |
| 15 | E-ACSL | `--temporal`: function address argument aborts | [draft](./frama-c-eacsl-temporal-function-address-argument.md) | [issue](./filing/15-eacsl-temporal-function-address-argument-issue.md), filed [#2815](https://git.frama-c.com/pub/frama-c/-/work_items/2815) | none | [sh](./repro/15-eacsl-temporal-function-address-argument.sh) | none (design choice) |
| 16 | E-ACSL | `loop variant len(s)` aborts (typing not performed) | [draft](./frama-c-eacsl-loop-variant-logic-function-application.md) | [issue](./filing/16-eacsl-loop-variant-logic-function-application-issue.md), filed [#2806](https://git.frama-c.com/pub/frama-c/-/work_items/2806) | [MR](./filing/16-eacsl-loop-variant-logic-function-application-mr.md), opened [!37](https://git.frama-c.com/pub/frama-c/-/merge_requests/37) | [sh](./repro/16-eacsl-loop-variant-logic-function-application.sh) | [validated](./patches/16-eacsl-loop-variant-logic-function-application.patch) |
| 17 | E-ACSL | `memcmp` replacement rejects overlapping buffers | [draft](./frama-c-eacsl-memcmp-overlapping-buffers.md) | [issue](./filing/17-eacsl-memcmp-overlapping-buffers-issue.md), filed [#2803](https://git.frama-c.com/pub/frama-c/-/work_items/2803) | [MR](./filing/17-eacsl-memcmp-overlapping-buffers-mr.md), opened [!34](https://git.frama-c.com/pub/frama-c/-/merge_requests/34) | [sh](./repro/17-eacsl-memcmp-overlapping-buffers.sh) | [validated](./patches/17-eacsl-memcmp-overlapping-buffers.patch) |
| 18 | E-ACSL | Runtime init empties `environ` | [draft](./frama-c-eacsl-memory-init-clobbers-environ.md) | [issue](./filing/18-eacsl-memory-init-clobbers-environ-issue.md), filed [#2802](https://git.frama-c.com/pub/frama-c/-/work_items/2802) | [MR](./filing/18-eacsl-memory-init-clobbers-environ-mr.md), opened [!33](https://git.frama-c.com/pub/frama-c/-/merge_requests/33) | [sh](./repro/18-eacsl-memory-init-clobbers-environ.sh) | [validated](./patches/18-eacsl-memory-init-clobbers-environ.patch) |
| 19 | WP | A probe drops the frame of the goal | [draft](./frama-c-wp-counter-examples-drops-frame.md) | [issue](./filing/19-wp-counter-examples-drops-frame-issue.md), filed [#2811](https://git.frama-c.com/pub/frama-c/-/work_items/2811) | [MR](./filing/19-wp-counter-examples-drops-frame-mr.md), opened [!42](https://git.frama-c.com/pub/frama-c/-/merge_requests/42) | [sh](./repro/19-wp-counter-examples-drops-frame.sh) | [validated](./patches/19-wp-counter-examples-drops-frame.patch) |
| 20 | Kernel (printer) | `_Alignas` printed inside the declarator | [draft](./frama-c-kernel-alignas-member-printed-after-declarator.md) | [issue](./filing/20-kernel-alignas-member-printed-after-declarator-issue.md), filed [#2812](https://git.frama-c.com/pub/frama-c/-/work_items/2812) | [MR](./filing/20-kernel-alignas-member-printed-after-declarator-mr.md), opened [!43](https://git.frama-c.com/pub/frama-c/-/merge_requests/43) | [sh](./repro/20-kernel-alignas-member-printed-after-declarator.sh) | [validated](./patches/20-kernel-alignas-member-printed-after-declarator.patch) |
| 21 | E-ACSL | `register` local aborts under full tracking | [draft](./frama-c-eacsl-register-local-full-mtracking.md) | [issue](./filing/21-eacsl-register-local-full-mtracking-issue.md), filed [#2804](https://git.frama-c.com/pub/frama-c/-/work_items/2804) | [MR](./filing/21-eacsl-register-local-full-mtracking-mr.md), opened [!35](https://git.frama-c.com/pub/frama-c/-/merge_requests/35) | [sh](./repro/21-eacsl-register-local-full-mtracking.sh) | [validated](./patches/21-eacsl-register-local-full-mtracking.patch) |
| 22 | E-ACSL | `Unregistered("__gmpz_clear")` with `<gmp.h>` | [draft](./frama-c-eacsl-gmp-symbol-unregistered.md) | [issue](./filing/22-eacsl-gmp-symbol-unregistered-issue.md), filed [#2816](https://git.frama-c.com/pub/frama-c/-/work_items/2816) | [MR](./filing/22-eacsl-gmp-symbol-unregistered-mr.md), not opened (awaits the maintainers' choice) | [sh](./repro/22-eacsl-gmp-symbol-unregistered.sh) | [validated](./patches/22-eacsl-gmp-symbol-unregistered.patch) |
| 23 | E-ACSL | `const` union global: implicit cast to `void *` | [draft](./frama-c-eacsl-static-const-union-cast.md) | [issue](./filing/23-eacsl-static-const-union-cast-issue.md), filed [#2795](https://git.frama-c.com/pub/frama-c/-/work_items/2795) | in 27's MR, [!26](https://git.frama-c.com/pub/frama-c/-/merge_requests/26) | [sh](./repro/23-eacsl-static-const-union-cast.sh) | in [27](./patches/27-eacsl-readonly-scalar-global-address.patch) |
| 24 | E-ACSL | Guarded quantifier: conjunct after the guard unchecked (**soundness**) | [draft](./frama-c-eacsl-guarded-exists-drops-conjunct.md) | [issue](./filing/24-eacsl-guarded-exists-drops-conjunct-issue.md), filed [#2793](https://git.frama-c.com/pub/frama-c/-/work_items/2793) | [MR](./filing/24-eacsl-guarded-exists-drops-conjunct-mr.md), opened [!25](https://git.frama-c.com/pub/frama-c/-/merge_requests/25) | [sh](./repro/24-eacsl-guarded-exists-drops-conjunct.sh) | [validated](./patches/24-eacsl-guarded-exists-drops-conjunct.patch) |
| 25 | Kernel | `offsetof(T, m[i])`, non-constant index (feature request) | [draft](./frama-c-kernel-offsetof-non-constant-index.md) | [issue](./filing/25-kernel-offsetof-non-constant-index-issue.md), filed [#2813](https://git.frama-c.com/pub/frama-c/-/work_items/2813) | [MR](./filing/25-kernel-offsetof-non-constant-index-mr.md), opened [!44](https://git.frama-c.com/pub/frama-c/-/merge_requests/44) | [sh](./repro/25-kernel-offsetof-non-constant-index.sh) | [validated](./patches/25-kernel-offsetof-non-constant-index.patch) |
| 26 | Libc | Socket headers: `sin_zero`, `ip_mreq`, `fd_set` | [draft](./frama-c-libc-socket-header-gaps.md) | [issue](./filing/26-libc-socket-header-gaps-issue.md), filed [#2814](https://git.frama-c.com/pub/frama-c/-/work_items/2814) | [MR](./filing/26-libc-socket-header-gaps-mr.md), opened [!45](https://git.frama-c.com/pub/frama-c/-/merge_requests/45) | [sh](./repro/26-libc-socket-header-gaps.sh) | [validated](./patches/26-libc-socket-header-gaps.patch) |
| 27 | E-ACSL | `mark_readonly` gets a `const` global's value, not its address | [draft](./frama-c-eacsl-readonly-scalar-global-address.md) | [issue](./filing/27-eacsl-readonly-scalar-global-address-issue.md), filed [#2794](https://git.frama-c.com/pub/frama-c/-/work_items/2794) | [MR](./filing/27-eacsl-readonly-scalar-global-address-mr.md), opened [!26](https://git.frama-c.com/pub/frama-c/-/merge_requests/26) | [sh](./repro/27-eacsl-readonly-scalar-global-address.sh) | [validated](./patches/27-eacsl-readonly-scalar-global-address.patch) (also fixes 23) |
| 28 | E-ACSL | Full tracking + clang: a literal stored inside a longer one splits its block | [draft](./frama-c-eacsl-full-mtracking-tail-merged-literals.md) | [issue](./filing/28-eacsl-full-mtracking-tail-merged-literals-issue.md), not filed | [MR](./filing/28-eacsl-full-mtracking-tail-merged-literals-mr.md), not opened | [sh](./repro/28-eacsl-full-mtracking-tail-merged-literals.sh) | [validated](./patches/28-eacsl-full-mtracking-tail-merged-literals.patch) (adds kernel `Demote_string_literal.demote_list`; changes 2 concurrency oracles; `format/` dev not run to the end) |
| 29 | E-ACSL | `\object_pointer` false on read-only data (literals, `const` arrays) | [draft](./frama-c-eacsl-object-pointer-readonly-static.md) | [issue](./filing/29-eacsl-object-pointer-readonly-static-issue.md), not filed | [MR](./filing/29-eacsl-object-pointer-readonly-static-mr.md), not opened | [sh](./repro/29-eacsl-object-pointer-readonly-static.sh) | [validated](./patches/29-eacsl-object-pointer-readonly-static.patch) |
| 30 | E-ACSL | `--validate-format-strings`: `"%u"` with a promoted `unsigned char` aborts | [draft](./frama-c-eacsl-format-promoted-argument-signedness.md) | [issue](./filing/30-eacsl-format-promoted-argument-signedness-issue.md), not filed (partly a question on `int`/`unsigned`) | [MR](./filing/30-eacsl-format-promoted-argument-signedness-mr.md), not opened | [sh](./repro/30-eacsl-format-promoted-argument-signedness.sh) | [validated](./patches/30-eacsl-format-promoted-argument-signedness.patch) (static fix; no existing oracle changes) |
| 31 | E-ACSL | `--validate-format-strings`: `%s` after a `double` checks the wrong argument | [draft](./frama-c-eacsl-format-fp-argument-slots.md) | [issue](./filing/31-eacsl-format-fp-argument-slots-issue.md), not filed | [MR](./filing/31-eacsl-format-fp-argument-slots-mr.md), not opened | [sh](./repro/31-eacsl-format-fp-argument-slots.sh) | [validated](./patches/31-eacsl-format-fp-argument-slots.patch) |

Not filed, by decision (see the catalog): Issues 2, 6, 7 and 11.

## How to file

1. **Issue first.** Open the issue from `filing/NN-*-issue.md`: the first line (without `# `) is the
   title, and everything below the HTML comment is the description.
2. **Order where texts reference each other:**
   - 23 and 27 cite each other: done (27 filed first, then 23, then 27's description edited).
   - 12 before 10.
   - 8 and 13 can go together.
3. **Replace the placeholders** with the real numbers: `#<issue>` and `#ISSUE-NN` in the texts, and
   `!<MR>` in MR 10.
4. **Merge request.** Fork `pub/frama-c`, create the branch named in the MR text from `3dff90fc70` (or
   current `master`), then apply the patch and push:

   ```sh
   git am --keep-non-patch patches/NN-<slug>.patch
   ```

   `--keep-non-patch` keeps the `[e-acsl]` / `[kernel]` / `[wp]` / `[libc]` prefix in the subject;
   plain `git am` strips it.
   - The commits are authored as Florian Stosse and carry a `Co-Authored-By: Claude` trailer. Each
     text also ends with an LLM-assistance line. Keep or drop both consistently.
   - MR 10's branch goes on top of 12's.
5. **Contributor Licence Agreement** (the owner's call): upstream asks for it on a first non-trivial
   contribution (`CLA.md`, `TCA.md`). Patches 13 (63 files) and 26 (16 files) are the largest.
6. **Lint and headers (2026-11-15):** upstream's own `./dev/check-files.sh -p HEAD~1`
   (`make check-lint` and `make check-headers` on the files each branch changes) was run on every
   branch with patches (all 22), in a git clone inside the image `framac-lint:3dff90f`
   (`framac-master-audit:3dff90f` plus ocp-indent 1.10.0, headache 1.08 and clang-format 19.1.7).
   A negative control confirmed that it fails on a mis-indented `.ml`, an unformatted `.c` and a
   missing header.
   - 20 passed as they were.
   - 13 (!28) and 08 (!32) failed clang-format on their new test file. Each branch got a second
     commit, "[e-acsl] clang-format the new test", which formats the test and updates its oracles
     (the default configuration of its test directory rerun clean). It was pushed as a fast-forward
     (a force-push was refused by the session's permission policy), and the patch files of 13 and 08
     now hold both commits (`git am` applies them in order). Both MR descriptions were updated.
   - The MR texts of 01, 09, 10, 12, 19, 20, 22, 25 and 26 now state the clean lint run.
   - New oracle files keep ptests' trailing spaces, as upstream oracles do.
7. **`make default-tests` (CONTRIBUTING.md step 8, 2026-11-16):** run once on all 21 merge-request
   branches merged together onto `3dff90fc70` (no merge conflict), and on pristine `3dff90fc70` as a
   baseline, in `framac-lint:3dff90f` as the non-root user `opam`. Run as root, the cram test
   `tests/misc/user_directories.unix.t` fails on pristine `master` too, because `chmod -w` does not
   stop root.
   - Baseline: exit 0, 6740 result logs.
   - Merged: exactly 7 oracle diffs, each one added `__e_acsl_full_init((void *)(& <formal>));` line.
     That is the intended effect of !28 (Issue 13, formals marked initialized) on the new tests of
     other merge requests: `constructs/incomplete_type` (!36), `constructs/iff_labelled_terms` (!31),
     `constructs/logic_app_reading_memory` (!37), `libc/default_source` (!40), `libc/getenv` (2
     oracles, !33) and `memory/unbounded_range` (!29). No existing upstream oracle changes. After
     promoting those 7, the whole `make default-tests` passes: exit 0, 6780 result logs.
   - So whichever of these merge requests lands after !28 (or !28 after them) needs those oracles
     regenerated. Each branch was not run on its own; the merged run covers every change at once.
   - Posted on 2026-11-16 as a note on each of the seven merge requests (!28, !29, !31, !33, !36,
     !37, !40), saying who regenerates the oracles depending on the merge order.

## Open questions for the owner

| # | Question |
| :-- | :-- |
| all | Only 01, 09, 10 and 12 add a `plugins/e-acsl/doc/Changelog` entry. Add entries to the others, or drop these four and leave the Changelog to the maintainers? |
| 10 / 12 | Two stacked MRs (current), or one combined MR? |
| 12 | Keep the 220-line generated oracle of the `stpcpy` test, or trim the test? |
| 13 | Ship the 57 promoted `gen_*.c` oracles in the MR (current), or let the maintainers promote them? |
| 15 | Which of the three fixes in the issue to propose, if any, once the maintainers answer. |
| 22 | The fix also makes `Rtl.Symbols.mem_vi` true for user functions linked to RTL ones, so a local named like one of them would no longer be monitored. Asked in #2816 (option 1, option 2 = separate table, or another approach); open the MR once they answer. |
| 25 | Accept non-constant indexes silently (current patch), warn, or restrict to GCC-like machdeps? The issue asks this. |
| 26 | Keep the `fd_set` part (independent), and should the dead `__USE_MISC`/`__USE_GNU` guards in `__fc_inet.h` go? Only glibc was compared. |
| 27 | Structs without bitfields keep per-field read-only marking (from e-acsl#223); the const-pointer case is real in the generated code, but no failing program was found. |
| 28 | Is a kernel API (`demote_list`) acceptable inside an E-ACSL MR? Should default mode use it too (4,000 asserted literals take 217 s on `master`)? Is the 467-line generated oracle of the new test acceptable? |
| 29 | Keep the impact counts (minmea 371/372, nettle 15/24) in the issue? Keep the `\object_pointer(stdin)` case in the test? File the bittree gap (`eacsl_memory_init` never calls `collect_safe_locations`, so standard streams are untracked) as its own issue? |
| 30 | `_Bool` reuses the letter `C`, so a rejected `_Bool` is named `'unsigned char'`; a new letter would shift 85 lines of the `printf.c` dev oracle. |
| 30 / 31 | The MR texts reference each other's issue (`#ISSUE-30`, `#ISSUE-31`): file both issues before filling them in. 31's issue notes the cosmetic `%n` message ("argument 1" for directive 2) without fixing it. |

## Identified, not filed

Each of these is worked around or documented in the pipeline. None is a defect to report as a bug:

| Item | Where | Why not filed |
| :-- | :-- | :-- |
| Issues 2, 6, 7, 11 | [catalog](./frama-c-e-acsl-issues.md) | Documented behaviour, deliberate convention, or changelog notes |
| E-ACSL resets `__e_acsl_sound_verdict` after `strto*`/`wcsto*` calls | `scripts/eacsl_toolchain.py` `rewrite_sound_verdict_resets` | By design: no model for those functions, so later verdicts are marked unsound |
| E-ACSL ignores a quantifier without an upper bound | [`../../troubleshooting/eacsl-and-fuzzing.md`](../../troubleshooting/eacsl-and-fuzzing.md) | Documented limitation (warning "Missing upper bound") |
| E-ACSL rejects pointers from uninstrumented libraries | same | Inherent to shadow memory |
| WP `Typed`: casts between pointer types, unions | [`../../troubleshooting/wp-and-guardrail.md`](../../troubleshooting/wp-and-guardrail.md) | Documented memory-model limitation; the pipeline uses `Bytes` |
| WP: no framing stub for variadic callees | [`../../troubleshooting/harnesses-and-seeds.md`](../../troubleshooting/harnesses-and-seeds.md) | Documented limitation |
| Frama-C libc missing headers and declarations (`<netinet/ip_icmp.h>`, glibc `__int8_t` aliases, Linux declarations) | `templates/fc_stubs/` | Coverage gaps, not wrong contracts; a candidate for one libc feature request later |

## Seen during the audit, not drafted

- **E-ACSL bittree model crashes on `int main(void)`.** It segfaults without `-M`; with `-M` the
  clang build aborts with exit 134. `main(int, char **)` is fine. Not investigated; noted in
  [`./frama-c-eacsl-memory-init-clobbers-environ.md`](./frama-c-eacsl-memory-init-clobbers-environ.md).
- **Dead branch in `e_acsl_temporal.c`.** `eacsl_temporal_save_return` tests a comma expression,
  which is always true. Noted in
  [`./frama-c-eacsl-temporal-function-address-argument.md`](./frama-c-eacsl-temporal-function-address-argument.md).
- **Cosmetic wrong names in E-ACSL libc-replacement diagnostics:** `memmove` reports "memcmp",
  `strcpy` reports "strlen" and `strncat` reports "strcat". Mentioned in issue 17 as a follow-up.
- **Kernel accepts `sizeof x` on an incomplete struct** in a file-scope initializer. Seen while
  probing `ip_mreqn`; not confirmed.
- **`--validate-format-strings` without `-M` rejects a literal format string.**
  `snprintf(t, sizeof t, "%u.%u.%u.%u", ...)` aborts with
  `snprintf: invalid format string (unallocated or unterminated)` unless full memory tracking is on
  (34.0~beta). Not analysed; noted in
  [`./frama-c-eacsl-format-promoted-argument-signedness.md`](./frama-c-eacsl-format-promoted-argument-signedness.md).
