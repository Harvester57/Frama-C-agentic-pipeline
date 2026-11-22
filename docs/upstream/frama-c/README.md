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
on 2026-11-09. It predates Issues 15 to 40, so do not rely on it alone for deduplication.

---

## Status update (2026-11-22)

This section is newer than the ones below and wins where they differ.

- **Drafted and validated, not filed: 50** (2026-11-22). With `--validate-format-strings`,
  `Functions.Libc.get_printf_argument_str` (`plugins/e-acsl/src/libraries/functions.ml:156`) falls
  into `assert false` for any `TEnum _` argument to `printf`, `fprintf`, `sprintf`, `snprintf`,
  `dprintf`, or `syslog` (`default_argument_promotion` in `cabs2cil.ml:3847` preserves `TEnum ei`),
  and `get_pkind_str` falls into `Options.fatal` (`unexpected argument type in printf`) for
  `enum E *` pointers (such as `%n` on a signed `enum *`, or mismatched `%p`/`%s`).
  - **Package:** analysis draft
    ([`./frama-c-eacsl-format-enum-argument.md`](./frama-c-eacsl-format-enum-argument.md)), issue
    text ([`./filing/50-eacsl-format-enum-argument-issue.md`](./filing/50-eacsl-format-enum-argument-issue.md)),
    MR text ([`./filing/50-eacsl-format-enum-argument-mr.md`](./filing/50-eacsl-format-enum-argument-mr.md),
    holding `#<issue>`), reproducer
    ([`./repro/50-eacsl-format-enum-argument.sh`](./repro/50-eacsl-format-enum-argument.sh) +
    [`./repro/50-eacsl-format-enum-argument.c`](./repro/50-eacsl-format-enum-argument.c)), and patch
    ([`./patches/50-eacsl-format-enum-argument.patch`](./patches/50-eacsl-format-enum-argument.patch),
    one commit `53ebd5fc4a` on `master` `189053d4a2`, 4 lines added and 2 changed in `functions.ml`
    plus `plugins/e-acsl/tests/format/printf_enum.c` with 14 sub-tests and 3 oracles).
  - **Validated** on upstream `master` `189053d4a2` in `framac-master-audit:189053d` via
    `revalidate.sh package 50`: `git am --keep-non-patch` clean (no mode changes), `printf_enum.c`
    fails on unpatched `master` (default and `dev`) and passes patched (default and `dev`), the
    entire `plugins/e-acsl` default suite and the entire `plugins/e-acsl/tests/format` `dev` suite
    pass with zero diffs on existing oracles, `./dev/check-files.sh -p HEAD~1` passes (`Lint 5
    file(s)`), and the 12-case reproducer goes from `RESULT: bug present (12 of 12 cases fail)` on
    both `master` `189053d4a2` and `34.0~beta` (`framac-analysis:latest`) to `RESULT: fixed`
    (12/12 pass). Stacks cleanly with Issue 30 (`!48`) via `git am --3way --keep-non-patch` in
    either order (`30+50` and `50+30`), passing both `printf_promoted.c` and `printf_enum.c` in
    `dev`.
  - **Duplicates:** live read-only API search of `pub/frama-c` issues and MRs (all states) on
    2026-11-22 found none.
  - **Overview text updated locally:** [`./filing/00-reports-overview-issue.md`](./filing/00-reports-overview-issue.md)
    adds a 22 November edit note and annex row `50` under E-ACSL (sync to live `#2832` awaits the
    owner's go-ahead; filing remains paused).

---

## Status update (2026-11-20)

This section is newer than the ones below and wins where they differ.

- **Overview issue [#2832](https://git.frama-c.com/pub/frama-c/-/work_items/2832) updated** (on
  the owner's go-ahead, synced from
  [`./filing/00-reports-overview-issue.md`](./filing/00-reports-overview-issue.md)): minimal edit
  adding a 20 November edit note, updating the annex version sentence for MetAcsl (`45`, `47` to
  `49`), adding annex rows for guarded `\old`/`\at` evaluation (E-ACSL, ref `old-guard`),
  `<sched.h>` `cpu_set_t` (Libc, ref `46`; live tracker duplicate check clean on 2026-11-20), and
  MetAcsl `47`, `48`, `49`, and updating `45` to state its patch is ready. Filing remains paused;
  no new issues or merge requests were opened.
- **Un-drafted items from [`../../troubleshooting/wp-and-guardrail.md`](../../troubleshooting/wp-and-guardrail.md)
  recorded locally only (not in `#2832`):** WP `ioctl` (`__va_ioctl_ptr` infinite range) and WP
  `Typed` `lsl` shift bounds are noted under [Identified, not filed](#identified-not-filed);
  ranged `\initialized` (`labels pre-analysis`, reproduced on `34.0~beta` only so far) and the
  `modbus_strerror` tail-call `assigns` sub-goal (not reproduced on a minimal standalone function)
  are noted under [Seen during the audit, not drafted](#seen-during-the-audit-not-drafted).

---

## Status update (2026-11-19)

This section is newer than the ones below and wins where they differ.

- **Full reassessment and local remediation of filed reports (`#2793` to `#2832`):** All 39 filed
  issues, their merge requests, patches, and reproducers (plus the overview `#2832`) were
  re-audited against upstream `master` (`b80fcac74f`) in `framac-master-audit:b80fcac`. Zero
  reports were questionable; 30 filed bugs plus `#2832` were solid; 9 items (8 filed + 1 local
  unfiled MR draft) needed revision and were remediated locally and re-validated end-to-end with
  [`../../../tools/upstream_audit/revalidate.sh`](../../../tools/upstream_audit/revalidate.sh) on
  `b80fcac74f` (`git am --keep-non-patch`, fail-before / pass-after tests, `plugins/e-acsl` +
  touched suites, `./dev/check-files.sh -p HEAD~1`, and installed reproducers):
  - **27 & 23 (`#2794`, `#2795`, `!26`):** Removed the preserved per-field `TComp` branch in
    `global_observer.ml` (`TArray _` -> `Cil.evar`, `_` -> `Cil.mkAddrOfVi`). Marking a non-first
    field (`&cs.b`) passed `_block_length(&cs.b) == sizeof(cs)` to `mark_readonly_region`, writing
    past the end of any multi-field `const struct` (aborts under `--rt-debug`) and emitting zero
    calls for an empty `const struct {}`. Updated `const_globals.c` (with `run.config_dev`
    `--full-mtracking --rt-debug`), the single affected existing oracle
    (`concurrency/oracle/gen_sequential_threads.0.c`), both reproducers, and the filing/draft texts.
  - **24 (`#2793`, `!25`):** Added `?(in_lhs=false)` to `visit_quantif_relations` in
    `bound_variables.ml`, closing both multi-variable nested implications inside a `\forall`
    hypothesis (`(0 <= i < n ==> 0 <= j < m) ==> i < n`) and a newly spotted sibling soundness bug
    (conjunction outside any implication hypothesis while unguarded variables remain, e.g.
    `0 <= i < n ==> 0 <= j && (j < m ==> i < n)`). Extended `quantif_conjunctions.c`, the
    reproducer, and the filing/draft texts.
  - **39 (`#2828`, `!56`):** Added `assigns errno` on all 9 `epoll_*` and `inotify_*` functions
    (preventing unsound dead-code elimination of `errno == EINTR` loops), replaced
    `#include <signal.h>` with `../__fc_define_sigset_t.h` in `sys/epoll.h`, added
    `initialization:sigmask` and `indirect:*sigmask` to `epoll_pwait`, added
    `indirect:event, indirect:event->events` to `epoll_ctl`, updated `sys_epoll_h.c` (both `x86_32`
    and `x86_64`, `EPOLL_CTL_DEL` with `NULL`, `EINTR` check, host glibc syntax check) and
    `sys_inotify_h.c`, noted intentional omission of `epoll_pwait2`, and synced
    [`../../../templates/fc_stubs/sys/epoll.h`](../../../templates/fc_stubs/sys/epoll.h) and
    [`../../../templates/fc_stubs/sys/inotify.h`](../../../templates/fc_stubs/sys/inotify.h).
  - **05 (`#2805`, `!36`):** Guarded `TSizeOfE` and `TAlignOfE` in `typing.ml` alongside
    `TSizeOf`/`TAlignOf`, tightened comments to cover incomplete arrays and enums, and added
    `TSizeOfE` cases (`sizeof(g)`, `sizeof(a)`) to `incomplete_type.c` and the reproducer.
  - **13 (`#2797`, `!28`):** Initialized `argc_ref` and `argv_ref` in `argv_alloca` in both
    segment (`initialize_static_region`) and bittree (`eacsl_initialize`) observation models so
    `\initialized(&argc)` / `\initialized(&argv)` via pointers no longer abort, squashed the patch
    into 1 clean commit on `b80fcac74f`, and added `main(int argc, char **argv)` to
    `issue-framac-177.c` and the reproducer.
  - **20 (`#2812`, `!43`):** Added `palignas true` to `TBuiltin_va_list` in `cil_printer.ml` so
    `_Alignas` on `__builtin_va_list` and `__builtin_va_list *` is not dropped under
    `-no-variadic-translation`; extended `tests/pretty_printing/alignas.c` and the reproducer.
  - **42 (`#2831`, `!59`):** Added optional leading sign `[-+]?` to `re_hexadecimal` in
    `Cfloat.ml` (for `Logic_const.treal` / `-float-print hex` negative literals) plus an explicit
    empty-digit guard (because Zarith `Z.of_string_base 16` silently returns `0` on `""`/`"-"`/`"+"`);
    extended `wp_acsl/float_literals.i` (non-exact `0.1f32`/`0.1F64` and `eva + reduc -float-print hex`
    run, 6 oracles across default and `qualif`).
  - **36 (`#2825`, `!53`):** Fixed the unclosed Markdown code fence on line 59 of
    [`./filing/36-eacsl-heap-zone-size-overflow-issue.md`](./filing/36-eacsl-heap-zone-size-overflow-issue.md)
    and parenthesized `(E_ACSL_HEAP_SIZE)` / `(E_ACSL_TLS_SIZE)` in
    [`./patches/36-eacsl-heap-zone-size-overflow.patch`](./patches/36-eacsl-heap-zone-size-overflow.patch).
  - **22 (`#2816` local MR draft), 14 (`#2800`), 00 (`#2832`):** Replaced `#ISSUE-22` with `#2816`
    and fixed the cross-TU shadowing example in
    [`./filing/22-eacsl-gmp-symbol-unregistered-mr.md`](./filing/22-eacsl-gmp-symbol-unregistered-mr.md);
    fixed the `Piff` interlang citation in
    [`./filing/14-eacsl-iff-labelled-term-issue.md`](./filing/14-eacsl-iff-labelled-term-issue.md);
    corrected three editorial lines (23, 38, 159) in
    [`./filing/00-reports-overview-issue.md`](./filing/00-reports-overview-issue.md).
- **Synced to GitLab (2026-11-19, on the owner's go-ahead):**
  - All 8 MR branches were built on `b80fcac74f` via
    [`../../../tools/upstream_audit/make_branches.sh`](../../../tools/upstream_audit/make_branches.sh)
    and force-pushed with `--force-with-lease` to `Harvester57/frama-c`: `!36` (`05`, `392ea01113`),
    `!28` (`13`, `74af5e0224`, squashed to 1 commit), `!43` (`20`, `1004c15a56`), `!25` (`24`,
    `add5b2bd60`), `!26` (`27`, `4e596579ef`), `!53` (`36`, `2deb0251ba`), `!56` (`39`,
    `0dc79ec324`), and `!59` (`42`, `5a98c87bac`).
  - All 8 MR descriptions (plus `!26`'s title) and all 9 changed issues (`#2793`, `#2794`, `#2795`,
    `#2797`, `#2800`, `#2805`, `#2812`, `#2825`, `#2832`) were updated via `glab api` and read back
    identical, preserving the live checkbox states (`['x', ' ']` on `!25`, `!26`, `!28`, `!36`,
    `!43`, `!53`, `!56`; `[' ', ' ']` on `!59`), with each MR verified at 1 commit and the exact
    file count of its patch. `#2828` (`39`) and `#2831` (`42`) were unchanged and untouched.

---

## Status update (2026-11-18)

This section is newer than the ones below and wins where they differ.

- **Filed: 28 to 40**, on the owner's go-ahead, from the account Harvester57. Asked which of 28 to
  40 to file first, the owner wrote "prepare doc-only patch for 40, then fill everything"; "fill"
  was read as "file".
  Every package up to 40 now has its issue filed; 22's merge request still waits for the
  maintainers' answer.
  - **Issues:** 28 to 31 as #2817 to #2820, 33 as #2821, 32 as #2822, 34 to 40 as #2823 to #2829
    (33 went before 32 so that 32's text could cite it; 37 before 38). 34 is an issue only.
  - **Merge requests:** 28 to 33 as !46 to !51, 35 to 39 as !52 to !56, and 40's manual fix as !57.
    Each is one commit on `95408044f7`, on its own branch of the fork `Harvester57/frama-c`, with
    the settings of the earlier ones (source branch removed on merge, maintainers may push, no
    squash). The CONTRIBUTING and CLA checkboxes are left for the owner to tick. No label,
    assignee or reviewer was set.
  - **Checks on each item:** the stored title and description were read back and are identical to
    the filing text; each merge request shows one commit and the file count of its patch, and
    GitLab reports all twelve as mergeable, without conflict.
- **Filed: 41** (later on 2026-11-18, from libmodbus `run-1`), as
  [#2830](https://git.frama-c.com/pub/frama-c/-/work_items/2830) with merge request
  [!58](https://git.frama-c.com/pub/frama-c/-/merge_requests/58), on the owner's go-ahead ("File
  issue + MR", chosen over a note on #2828): `<sys/ioctl.h>` defines `TIOCMGET`/`TIOCMSET` but not
  the `TIOCM_*` modem-line bits. The package (issue text, MR text, reproducer, patch) was written
  and checked the same day:
  - **Base:** upstream `master` moved to `b80fcac74f` on 2026-11-17 (one WP merge, nothing under
    `share/libc` or `tests/`). The audit container's tree was moved to it, rebuilt and reinstalled;
    the image itself is still `95408044f7`.
  - **Eleven names, not fourteen:** the patch adds the names glibc's `<sys/ioctl.h>` defines.
    `TIOCM_OUT1`, `TIOCM_OUT2` and `TIOCM_LOOP` exist only in Linux `<asm-generic/termios.h>` (gcc
    with glibc rejects them after `<sys/ioctl.h>`), so they are named in the texts and left out.
  - **Validated** with `revalidate.sh package 41`: the new test fails on `master`'s header and
    passes with the patch; `plugins/e-acsl/tests`, `tests/libc` and `tests/variadic` pass; lint
    passes; the reproducer goes from 11 failures of 11 to `RESULT: fixed`.
  - **Duplicates:** the tracker was searched live (read-only API); none. #2828 has no reply yet.
  - **As filed:** branch `fix/libc-ioctl-modem-lines` on the fork, one commit (`03a454ea4b`) on
    `b80fcac74f`, with the settings of the earlier merge requests and the two checkboxes left for
    the owner. Both stored texts were read back (identical) and rendered (no mention, links to
    #2828, #2830, !45 and !56). GitLab reports !58 as mergeable, one commit, three files.
- **Filed: 42** (2026-11-18), as [#2831](https://git.frama-c.com/pub/frama-c/-/work_items/2831)
  with [!59](https://git.frama-c.com/pub/frama-c/-/merge_requests/59): WP reads only decimal
  floating-point literals.
  - **Three symptoms, one function** (`Cfloat.parse_literal`): a hexadecimal literal without
    suffix, such as `DBL_MAX` from Frama-C's `<float.h>`, is rejected (a hypothesis is lost, a
    lemma stops WP); with `-wp-model +real` a suffixed one (`0x1.8p1f`) is read as 0 and
    `0x1.8p1f == 0.0` is proved; the `f32` and `f64` suffixes are rejected.
  - **Package:** issue text, MR text, a prover-free reproducer and a patch (21 lines added and 4
    removed in `Cfloat.ml`, and a test with four oracles), validated on `master` `b80fcac74f`.
    The checks that ran are in
    [`./frama-c-wp-hexadecimal-float-literals.md`](./frama-c-wp-hexadecimal-float-literals.md).
  - **As filed:** on the owner's go-ahead ("check expf now and then fill the issue and merge
    request"). Branch `fix/wp-hexadecimal-float-literals` on the fork, one commit (`e49fe7c9f2`,
    tree `27772c3d1c`) on `b80fcac74f`, with the settings of the earlier merge requests and the
    two checkboxes left for the owner. Both stored texts were read back (identical) and rendered
    (no mention, no strikethrough). GitLab reports !59 as mergeable, one commit, six files.
  - **Credit:** both texts name the `frama-c-discuss` report (2026-10) that showed the first
    symptom, and link it. The link was not opened from the filing session (the archive sits
    behind an anti-harvesting button).
- **Filed on 2026-11-18: an overview issue** for the maintainers,
  [#2832](https://git.frama-c.com/pub/frama-c/-/work_items/2832), text
  [`./filing/00-reports-overview-issue.md`](./filing/00-reports-overview-issue.md), title
  "Discussion: priorities for the reports #2793 to #2831, and how to send further findings".
  39 issues and 35 merge requests went up in four days, so it ranks them (first #2793, #2800,
  #2797, #2831 and #2798 with #2799), indexes them by component and asks three questions: whether
  bittree is still supported, how to send further findings, and whether to combine or draft merge
  requests. It also says the CLA is not signed yet: the owner said to post without confirming
  that sentence, so correct it by editing the issue if it is wrong.
  - **Filing is paused** until the maintainers answer on content. The first proposal made to the
    owner on 2026-11-18 kept an exception for a finding where an analysis gives a wrong verdict.
    Later that day the owner asked to discuss in this main issue before proposing any other
    issue or merge request, so the exception is gone: 43 and the candidates of the hunt wait
    too. The owner then asked for another title and said to post it: the go-ahead covered this
    issue only. The tracker was read just before: 39 issues and 35 merge requests, all open.
  - **It now lists the findings that are not filed** (added on 2026-11-18 by the session that
    ran the hunt): the question on enumeration constants (N1, a deliberate upstream change), a
    table of the wrong-answer findings by component, a sentence on the smaller ones, and an
    annex at the end with every unfiled finding in one line (45 lines, by component, with the
    labels of the candidates file so that an answer maps back to it).
    Question 2 asks which of them the maintainers want and in what form. The compilation
    database finding (H13) is left out of that public text: from a reading of the code it may
    allow command execution, which was not demonstrated, so its channel is the owner's call.
  - **Grouping on the tracker:** `git.frama-c.com` runs GitLab 19.4.6 Community Edition. An issue
    can only have tasks as children (no epic, no issue under an issue), and merge requests have
    no hierarchy. The account Harvester57 is not a project member: on its own issues it can edit
    the text and comment, but cannot set labels, link items or add child items. So the grouping
    we can do ourselves is the list of references in the overview text.
  - **Checkboxes as of 2026-11-18:** !25 to !58 have the CONTRIBUTING box ticked and the CLA box
    unticked; !59 has neither.
- **Drafted, not filed, no number yet** (2026-11-18, libmodbus `run-1`):
  [`./frama-c-eacsl-old-term-under-guard.md`](./frama-c-eacsl-old-term-under-guard.md). E-ACSL
  evaluates `\old(p->f)` at function entry even when `\old(p) == \null ||` makes the clause true,
  and aborts a valid call. Reproduced on `34.0~beta` and on `35.0~~dev` (`b80fcac`).
  - **Reassessed the same day: confirmed, and wider.** Default options are enough. The `==>`
    form, the behavior form (`assumes p != \null`), a division and a labelled `\at` in the body
    fail the same way: any `\at` term is evaluated at its label with blocking RTE checks.
  - **It contradicts the reference manual** (lazy `||`, `&&`, `==>`), the user manual lists no
    such limit, and the live tracker has no duplicate.
  - **Cause read:** `Translate_ats.for_stmt`. No patch.
  - **Frama-C's libc has the shape:** with `e-acsl-gcc -L`,
    `recvfrom(fd, buf, n, flags, NULL, NULL)` aborts.
  - **Listed in the annex of #2832** (ref `old-guard`) since 2026-11-20, on the owner's go-ahead.
- **Drafted, not filed: 43** (2026-11-18): E-ACSL and real constants that are not exactly a
  `double`. Found while looking for siblings of 42. The go-ahead of that day covered 42 only.
  - **Two symptoms, one function** (`Gmp.Q.normalize_str`): with an exponent or in hexadecimal
    notation (`1e-9`), Frama-C stops with
    `Unexpected error (E_ACSL__Gmp.Q.Not_a_decimal("1e-9"))`; a `long double` constant (`0.1L`)
    is 0 at run time without any message, so `0.1L == 0` holds and `0.1L > 0.05` aborts. The
    second one is a wrong verdict, which matters for the pause proposed above.
  - **Package:** issue text, MR text, a reproducer and a patch (12 lines added and 20 removed in
    `gmp.ml`, one sentence in `gmp.mli`, and a test with two oracles), validated on `master`
    `b80fcac74f` with `revalidate.sh package 43`. The checks that ran are in
    [`./frama-c-eacsl-real-constant-notation.md`](./frama-c-eacsl-real-constant-notation.md).
  - **Not done:** no branch pushed, no issue, no merge request. The MR text holds `#<issue>`.
- **Drafted, not filed: 44** (2026-11-18): the contract of `strlcat` in `share/libc/string.h`.
  Found by the session that proved reference bodies of the pipeline's own `strlcpy` and
  `strlcat` contracts. Prepared during the pause, without a go-ahead to file.
  - **Two wrong clauses.** `ensures \result == strlen(dest) + strlen(src)` reads the length of
    `dest` after the call, and `assigns dest[strlen(dest)..n]` includes one byte past the `n`
    bytes.
  - **Wrong verdicts from ordinary calls:** Eva gives `{7}` for a call that returns 4, with no
    alarm (two checks of the reproducer are invalid), and loses a structure field that follows
    the buffer. WP proves a postcondition that the compiled program violates.
  - **A weak precondition too:** `separation` covers only the first `strnlen(src, n-1)` bytes
    of `src`, so a call that writes over the NUL of `src` is accepted. The owner said to add
    the stronger form to the patch ("Yes, add it") once it was measured to change no oracle of
    `tests/libc` or of the E-ACSL suite.
  - **Package:** issue text, MR text, a reproducer (9 checks: 9 fail before, 0 after, on
    `master` `b80fcac74f` and on `34.0~beta`) and a patch (four clauses, a `tests/libc` test
    with its oracle, and the `string_h` oracle, which gets more precise), validated with
    `revalidate.sh package 44`. The checks that ran are in
    [`./frama-c-libc-strlcat-contract.md`](./frama-c-libc-strlcat-contract.md).
  - **Side effect:** with the patched header, `frama-c -e-acsl` no longer fails on a `strlcat`
    call (candidate L4 of the hunt). The E-ACSL defect itself is not fixed.
  - **Listed in #2832** since 2026-11-18, 21:56 UTC, on the owner's request ("update the main
    discussion but don't fill a unitary issue for this yet"): a dated note, a Libc row in the
    table of wrong-answer findings, a row `44` in the annex (46 lines now) and one sentence in
    the annex row L4. The stored description was read back and is identical to
    [`./filing/00-reports-overview-issue.md`](./filing/00-reports-overview-issue.md).
  - **Not done:** no branch pushed, no issue of its own, no merge request. The MR text holds
    `#<issue>`.
- **Drafted, not filed: 45** (2026-11-18; patch and MR built and validated on 2026-11-20): MetAcsl
  refuses `\result` in a `\postcond` property (`\result meaningless`). It is a report for the
  MetAcsl tracker, [`pub/meta`](https://git.frama-c.com/pub/meta/-/issues) (project id 869), kept
  in this folder because its drafts follow the same layout. Found by package R of
  [`../../plans/metacsl-exploitation-plan.md`](../../plans/metacsl-exploitation-plan.md).
  - **Package:** analysis draft
    ([`./frama-c-metacsl-result-in-postcond.md`](./frama-c-metacsl-result-in-postcond.md)), issue
    text, MR text (holding `#<issue>`), `git format-patch` file on `pub/meta` `master`
    `4f43801390`, and reproducer (2 cases refused before on `34.0~beta` / 0.12~beta and unpatched
    `master` `4f43801390`; `plain: 3 / 3 proved`, `plain_violated: 2 / 3 proved`,
    `guarded_violated: 2 / 3 proved` after).
  - **Patch and validation:** threads `?(with_result=false)` from `process_property` (true only for
    `Postcond`) to `process_meta_termassoc` in `meta_parse.ml`, calling `Logic_typing.add_result`
    with `Kernel_function.get_return_type kf` (plus `Ast_types.C.add_ghost` for ghost functions,
    guarded on `Ast_types.C.is_fun (Kernel_function.get_type kf)` so `Meta_deduce.dummy_unpack`
    with `Cil_datatype.Kf.dummy` does not fatal in `getReturnType`, and without
    `remove_qualifiers_deep` so `const int *` keeps its pointed-to `const` and passes `-check` and
    `\assert_type`), updates `README.md` and `CHANGELOG.md`, and adds `tests/meta/postcond_result.c`
    (10 oracles across `oracle/` and `oracle_fold/`). Built in a throwaway `framac-analysis:latest`
    container (with only `meta_parse.ml`'s post-34.0~beta `PLpointer_comparable` line removed for
    the container build; not in the patch); `tests/meta` (26 default + 26 fold) and `tests/meta-wp`
    (12 default + 12 fold) pass with 0 diffs against unpatched `master` on all 66 existing runs,
    and `tests/meta-deduce` has 0 diffs. Stacks cleanly with 47, 48 and 49 via
    `git am --keep-non-patch --3way` in either order (`45, 47, 48, 49` or `47, 48, 49, 45`; only
    `CHANGELOG.md`'s `# Version dev` conflicts; stacked build passes 31/31 `tests/meta`, 12/12
    `tests/meta-wp` in both configurations and all four reproducers exit 0).
  - **Listed in #2832** since 2026-11-18, on the owner's request ("Draft upstream report, but
    don't fill it, update main discussion"): a dated note and a row `45` in a new MetAcsl table
    at the end of the annex. Updated in #2832 on 2026-11-20 to note the built patch and `pub/meta`
    `4f43801390` run.
  - **Not done:** no issue on `pub/meta`, no branch, no merge request.
    [`../../../tools/upstream_audit/file_upstream.py`](../../../tools/upstream_audit/file_upstream.py)
    files on `pub/frama-c` only.
- **Drafted, not filed: 46** (2026-11-19). The libc's `<sched.h>` has no `cpu_set_t`, no `CPU_*`
  macros and no `sched_setaffinity`/`sched_getaffinity` under `_GNU_SOURCE`. This stopped
  nginx-1.31.9 run-1 at Phase 0 (`no_unit_parsed`).
  - **Package:** issue text
    ([`./filing/46-libc-sched-cpu-set-issue.md`](./filing/46-libc-sched-cpu-set-issue.md)) and a
    reproducer ([`./repro/46-libc-sched-cpu-set.c`](./repro/46-libc-sched-cpu-set.c)). Frama-C
    rejects it (rc 1) on `34.0~beta` and on `master` `b80fcac74f`; gcc accepts it (rc 0). The
    analysis is in [`./frama-c-libc-sched-cpu-set.md`](./frama-c-libc-sched-cpu-set.md).
  - **Pipeline workaround:** `templates/fc_stubs/fc_compat_types.h` (`cb78e8b`).
  - **Duplicates:** live tracker searched on 2026-11-20 (`cpu_set_t`, `sched_setaffinity`, `sched.h`); none.
  - **Listed in #2832** (annex ref `46`) since 2026-11-20. **Not done:** no patch, no MR text, no issue.
- **Drafted, not filed: 47, 48 and 49** (2026-11-20), three MetAcsl reports for
  [`pub/meta`](https://git.frama-c.com/pub/meta/-/issues) found while adding MetAcsl properties to
  the E-ACSL build (package C of [`../../plans/metacsl-exploitation-plan.md`](../../plans/metacsl-exploitation-plan.md)). Each has an analysis
  draft, an issue text, an MR text, a `git format-patch` file on `pub/meta` `master`
  `4f43801390`, and a reproducer run in `framac-analysis:latest` (Frama-C 34.0~beta, MetAcsl
  0.12~beta). The patches were built in throwaway containers of that image, on `master` with one
  line of `meta_parse.ml` (`PLpointer_comparable`, absent from 34.0~beta) removed; that removal is
  not in the patches. Both `tests/meta` and `tests/meta-wp` (default and `fold` configurations) were
  run for every patch with zero regressions; lint/header checks and `meta-deduce` deduction checks
  (no SWI-Prolog) were not run. Stacked with `git am --keep-non-patch --3way` (47, 48, 49),
  `meta_annotate.ml` auto-merges cleanly (only the `# Version dev` line of `CHANGELOG.md`
  conflicts), all three reproducers exit 0, and all ten new test oracles match byte-for-byte.
  - **47:** at a call to a function known by its contract, MetAcsl copies the callee's `Old`, `Pre`
    and `Here` labels into the `\written` and `\read` instances placed in the caller. `Old` makes
    the kernel, WP (`LabelError`) and E-ACSL (`invalid label 'Old' within statement annotation`)
    refuse the annotation; `Pre` is accepted but means the caller's pre-state, and `Here` in
    `assumes` or `assigns` means the post-state under an `After` property, so WP proves false
    properties in both cases. The fault is MetAcsl's, not E-ACSL's, contrary to the first
    troubleshooting entry. The patch maps `Old`, `Pre` and `Here` to MetAcsl's `Before` and adds
    `tests/meta/callee_labels.c` (behavior-guarded `assumes` checks marked `\flags(fold:no)` so the
    fold oracles do not encode `-meta-fold`'s pre-existing `assumes` sharing bug). Related, not the
    same: pub/meta#4.
  - **48:** under `-meta-fold`, `create_call` in `meta_annotate.ml` builds the call without
    `~loc`, so every folded instance has no location (`<unknown>:0` at run time under E-ACSL). The
    `post`/`post_fold` wrappers of `external_assigns`/`passthrough_from` drop it too, with or
    without folding. The patch passes the property's location, adds a `CHANGELOG.md` entry and
    regression test `tests/meta/fold_location.c` (exercising `create_call`, `post` and `post_fold`
    under `-report`), and updates `tests/meta-wp/oracle_fold/typing.0.res.oracle`.
  - **49:** feature request. A call to a function without any specification (libc from the host
    headers under `e-acsl-gcc`) gets no `\writing`/`\reading` instance and no warning, unlike a
    behavior without `assigns`. The patch puts all three missing-footprint warnings (no
    specification, `WritesAny` and `\reading`'s `FromAny`) under warning category `no-footprint`
    with call-site locations (`~loc`), and adds `tests/meta/no_footprint.i` covering `\writing` and
    `\reading`. Not patched: MetAcsl's `addr_of_tlval` and `Logic_const.term` calls in
    `meta_annotate.ml` omit `~loc` (defaulting to `Kernel.gen_loc`), so every `\written`, `\read`
    and `\called` term carries `<unknown>:0` — an ordinary out-of-bounds `*p = 1` write as well as
    an overflowing `memcpy` stops in the instance's E-ACSL validity guard at `<unknown>:0` before
    the RTE/libc check; the issue asks the maintainers about fixing term locations and optionally
    validity-guarding instances. The issue cites 47 and 48 as `#ISSUE-47` and `#ISSUE-48`.
  - **Listed in #2832** (annex refs `47`, `48`, `49`) since 2026-11-20. **Not done:** no issue,
    no branch, no merge request.
    [`../../../tools/upstream_audit/file_upstream.py`](../../../tools/upstream_audit/file_upstream.py)
    files on `pub/frama-c` only.
- **Candidates from the hunt of 2026-11-18, not drafted:** more defects of the same families
  (a literal read twice, hand-written text matching, WP's constant folding, the contracts of
  Frama-C's libc), found by the session that drafted 43 and its four subagents, and every one
  re-run on `master` `b80fcac74f`. Six reviewer subagents on another model then gave a second
  opinion on each (25 candidates: 23 confirmed, 2 not bugs to report, no duplicate on the
  tracker) and found 21 more. Several give a wrong proof or a wrong verdict from ordinary
  input; the most serious is that an enumeration constant is typed unsigned (N1). They are
  listed, ranked, with their reproducers, in
  [`./frama-c-hunt-2026-11-18-candidates.md`](./frama-c-hunt-2026-11-18-candidates.md).
- **40 now has a patch:** a manual-only fix of the two sentences about the JSON report
  (`"time"` is in seconds; `"cached"` counts prover results read from the cache, never Qed), in
  [`./patches/40-wp-report-per-prover-results.patch`](./patches/40-wp-report-per-prover-results.patch).
  - Its merge request says "Related to #2829", not "Closes": the feature request stays open.
  - Checked: `git am --keep-non-patch`, `./dev/check-files.sh -p HEAD~1`, and both values on
    `master` (`-wp-msg-key prover` prints `Valid (15ms)` where the report has `"time": 0.0154`).
    The manual was not built: the audit image has no LaTeX.
- **How the branches were made:** `git am --keep-non-patch` of each patch file on `master` inside
  the audit container, with author and committer set to the GitLab noreply address, then one
  `git bundle` fetched into a host clone and pushed with explicit refspecs. The host clone has
  `core.autocrlf=true`, so no patch was applied on the host.
- **Tools kept for the next filing:**
  [`../../../tools/upstream_audit/make_branches.sh`](../../../tools/upstream_audit/make_branches.sh)
  builds, checks and bundles the branches;
  [`../../../tools/upstream_audit/file_upstream.py`](../../../tools/upstream_audit/file_upstream.py)
  creates an issue or a merge request from its filing text, refuses a leftover placeholder or an
  existing title or branch, reads the item back, and records the number in `ledger.json` beside
  it. Neither retries, and both act only when run: filing still needs the owner's go-ahead.
  - **Seen with 41:** `make_branches.sh` builds on the container's `master`, which is
    `95408044f7` in the image, so fast-forward it first when upstream has moved (41's draft has
    the commands). Two defects of `file_upstream.py` were corrected after the filing
    (uncommitted): its "CRLF in the filing text" check could never fire, because `read_text`
    converts line endings (it now reads bytes; the texts of 41 were checked byte by byte, no CR);
    and `mr` read the commit list at once, got 0 commits for !58 and ended with "CHECK FAILED" on
    a correct merge request (it now waits for the commits as for the diff).
- **`closes_issues` is empty for every merge request** of `pub/frama-c`, old and new: the project
  has `autoclose_referenced_issues` off. "Closes #N" still links the two, but merging will not
  close the issue.
- **Text changes made while filing:** 29's merge request cites #2826 and #2827 for the two bittree
  defects of its closing note; 40's issue says a manual-only merge request is sent.
- **Open questions settled by filing as they stood:** the owner did not answer the rows of 28 to
  39 in "Open questions for the owner" one by one, so each package went up with the option that
  row calls "current". The ones that shape what the maintainers see:
  - 33 is filed although upstream tracks the defect privately as e-acsl#118 (its text says so);
  - 30, 31 and 32 are three merge requests, and 33 a fourth that regenerates three oracles;
  - 34 is one issue for the kernel and the libc parts;
  - 28 adds a kernel function (`demote_list`) inside an E-ACSL merge request;
  - 39 keeps the packed attribute on `struct epoll_event`;
  - 35 leaves `#define __restrict__` in `features.h`, and 36 leaves `tls:N` unread.
  Any of these can still change on the merge request if the maintainers or the owner prefer.
- **Rendering checked:** each stored description was rendered through GitLab's markdown endpoint.
  No user mention, no strikethrough (`35.0~~dev` stays literal), every code block closed, and the
  `#N` / `!N` links are the intended ones.
- **Not run:** `make default-tests` as a whole on the new branches (the suites named in each
  merge request were), 32-bit targets, and the manual build for !57.
- **Patch 39** was corrected before filing (four new files were created executable); see the
  2026-11-17 section.

## Status update (2026-11-17)

This section is newer than the one below and wins where they differ.

- **Upstream moved:** `master` is `95408044f7` (2026-11-16, the 34.0 Selenium release merged; 30
  commits after `3dff90fc70`). It changes `plugins/e-acsl/src/analyses/typing.ml`, which patches 04
  (!29), 05 (!36) and 16 (!37) also change. All three, and 28 to 31, still apply
  (`git apply --check`). GitLab reports !36 and !37 as mergeable and has not computed !29. None of
  the three filed patches was rebuilt on the new base.
- **Images:** `framac-master-audit:3dff90f`, its `-p28` to `-p31` variants and `framac-lint:3dff90f`
  no longer exist on the host (gone since the disk-full incident of 2026-11-17), and their recipe
  was never recorded. The recipe is now
  [`../../../tools/upstream_audit/Dockerfile`](../../../tools/upstream_audit/Dockerfile); it built
  `framac-master-audit:9540804` (8.6 GB: `master` `95408044f7`, ocp-indent 1.10.0, headache 1.08,
  clang-format 19.1.7, alt-ergo 2.6.4, why3 1.8.2, Z3 4.13.3, CVC5 1.1.2). One image now serves the
  builds and the lint.
- **28 to 31 re-validated on `95408044f7`** with
  [`../../../tools/upstream_audit/revalidate.sh`](../../../tools/upstream_audit/revalidate.sh), one
  patch per branch from `master`. Every step gave the expected result:
  - `git am --keep-non-patch` applies each patch.
  - The reproducer shows the bug on pristine `master` and the documented output with the patch.
  - Each new test fails on `master`'s sources and passes with the patch: 28 in the default
    configuration (generated code), 29 and 30 in the default and `dev` configurations, 31 in `dev`
    (a runtime fix; its default oracle does not depend on it). 28's test passes in `dev` on
    `master`, as its commit message says: the suite compiles with gcc and `-fno-merge-constants`.
  - The default configuration of the whole E-ACSL suite passes with each patch (198 result logs).
  - `./dev/check-files.sh -p HEAD~1` passes for each. Negative controls on the new image: a
    mis-indented `.ml`, an unformatted `.c` and a `.ml` without its licence header are each rejected.
  - Cases that must still abort do: `%u` with a `signed char`, `%d` with an `unsigned int` and
    `%lu` with an `unsigned char` (30); an unterminated string after a `double`, reported on its own
    directive (31); `\object_pointer` one byte before and two past a `const` array (29).
- **Not-run items of 2026-11-16, now run:** the `format/` `dev` configuration with 28 (`fprintf.c`,
  `printf.c` with its 380 cases, `sprintf.c`) passes; with 30 and 31 together (`git am`, then
  `git am --3way`), the `format/` `dev` configuration (the three upstream tests and the two new
  ones) and the default configuration of the whole E-ACSL suite pass. Each `dev` run took about
  11 s: an abort in a container now takes 6 ms on this host, with the core limit at 0.
- **Still not run for 28 to 31:** 32-bit targets (no 32-bit libc in the image), and `make
  default-tests` outside E-ACSL for 28, which changes the kernel module `Demote_string_literal`
  (the old `demote` keeps its behaviour; E-ACSL is its only caller checked).
- **Fork:** `Harvester57/frama-c` is `internal` since 2026-11-17 (an admin lifted the instance
  restriction), so reviewers can fetch the branches.
- **Triage by the maintainers (2026-11-17), no comment on content yet:** the E-ACSL issues got the
  `e-acsl` label; #2800, #2801 and #2808 are assigned to `jischard`, #2811 to `lcorrenson`; !27 is
  under review by `perrelle`. 15 (#2815) and 22 (#2816) still wait for their design answer.
- **Drafted, not filed (2026-11-17): 32 to 40.** Nine candidates from the pipeline's runs
  and from the earlier audit notes, analysed on `95408044f7`. All nine reproduce on `master`
  and on `34.0~beta` (`framac-analysis:latest`): in the second run the nine scripts printed the
  same output on both, apart from the Alt-Ergo version and the times in 40. Seven have a patch (32, 33, 35, 36, 37, 38, 39); 34 and 40 are issues only.
  - **Second run of every patch**, after the drafting agents' own validation, with `revalidate.sh`
    in fresh containers:
    - `git am --keep-non-patch` applies each on `95408044f7`. No patch changes the mode of an
      existing file or creates an executable one (after the correction of 39 below).
    - Each reproducer prints the documented "before" output on the pristine image and the
      documented "after" output with the patch installed.
    - Each new test fails on `master`'s sources and passes with the patch: 33 in the default and
      `dev` configurations; 35 and 39 in the default one (a syntax error, and
      `fatal error: sys/epoll.h`); 32, 36, 37 and 38 in `dev` (runtime fixes; their default oracles
      do not depend on the fix).
    - The default configuration of the whole E-ACSL suite passes with each patch, and so do
      `tests/syntax` with 35 and `tests/libc` with 39.
    - `./dev/check-files.sh -p HEAD~1` passes for each.
  - **Combinations run:** 30, 31 and 32 as a stack (`format/` in `dev`, and the whole E-ACSL suite
    in the default configuration); 33 alone with `format/` in `dev`; 37 and 38 together
    (`special/` in `dev`, and both reproducers: every line passes, including the `-G clang` line
    that 38 alone leaves failing).
  - **Corrected during the second run:** patch 39 carried two file-mode changes
    (`100644` to `100755`) and was re-exported without them. A read of the seven patches
    (2026-11-18) then found that the same patch still created four new files as executable
    (`share/libc/sys/epoll.h`, `share/libc/sys/inotify.h` and their two test sources), which the
    check of that time did not look for. It was re-exported again (from commit `732f33be36`; `git
    am` gives the same tree), `revalidate.sh` now also reports `create mode 100755`, and the whole
    `package 39` run was repeated on the new file: every step as before.
  - **What the read covered (2026-11-18):** every source hunk of 32, 33, 35, 36, 37, 38 and 39,
    line by line, with 32 and 37 checked against the upstream code around them: nothing else
    found. The new test sources were read; their oracles were checked by running the tests, not
    by reading them. The 8,400 lines of regenerated oracles in 33 were classified mechanically:
    every removed line has an added counterpart that differs only by a string literal replaced
    with its `__fc_lit_string` global or by line wrapping, and the added lines are those globals,
    their `store_block` / `mark_readonly` / `full_init` / `delete_block` calls, the
    `__e_acsl_globals_init` scaffolding, and the tracking of two locals passed to a format
    function (`buf`, `pstr`). The `signal_eval` literals change too because that test helper
    passes its argument to `fprintf("%s")`.
  - **Limits stated in the packages:** 32 leaves POSIX numbered `*` arguments (`%2$*1$d`)
    unchecked. 33 regenerates three existing default oracles (`gen_printf.0.c`, `gen_fprintf.0.c`,
    `gen_sprintf.0.c`), and upstream already tracks the defect privately as e-acsl#118 (named in a
    comment of its test configuration). 36 does not make `--zone-sizes tls:N` work (the value is
    never read). 38 is complete under `-G clang` only with 37.
  - **Not run:** 32-bit targets; 33 together with 30 to 32 (the `gen_*.0.c` oracles of their tests
    then need regenerating); the bittree model on test directories other than `special/` and
    `memory/`; `make default-tests` as a whole (only the suites named above).
  - **Duplicates:** each drafting agent searched the tracker through the read-only API (issues and
    merge requests, all states) and found none. Neighbours named in the texts: #980 (closed),
    #2802 / !33, #2807, #2810 / !41.

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
  after on `master` `3dff90fc70` (01 to 27), `95408044f7` (28 to 40), `b80fcac74f` (41 to 44), or
  `189053d4a2` (50).

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
| 28 | E-ACSL | Full tracking + clang: a literal stored inside a longer one splits its block | [draft](./frama-c-eacsl-full-mtracking-tail-merged-literals.md) | [issue](./filing/28-eacsl-full-mtracking-tail-merged-literals-issue.md), filed [#2817](https://git.frama-c.com/pub/frama-c/-/work_items/2817) | [MR](./filing/28-eacsl-full-mtracking-tail-merged-literals-mr.md), opened [!46](https://git.frama-c.com/pub/frama-c/-/merge_requests/46) | [sh](./repro/28-eacsl-full-mtracking-tail-merged-literals.sh) | [validated](./patches/28-eacsl-full-mtracking-tail-merged-literals.patch) (adds kernel `Demote_string_literal.demote_list`; changes 2 concurrency oracles) |
| 29 | E-ACSL | `\object_pointer` false on read-only data (literals, `const` arrays) | [draft](./frama-c-eacsl-object-pointer-readonly-static.md) | [issue](./filing/29-eacsl-object-pointer-readonly-static-issue.md), filed [#2818](https://git.frama-c.com/pub/frama-c/-/work_items/2818) | [MR](./filing/29-eacsl-object-pointer-readonly-static-mr.md), opened [!47](https://git.frama-c.com/pub/frama-c/-/merge_requests/47) | [sh](./repro/29-eacsl-object-pointer-readonly-static.sh) | [validated](./patches/29-eacsl-object-pointer-readonly-static.patch) |
| 30 | E-ACSL | `--validate-format-strings`: `"%u"` with a promoted `unsigned char` aborts | [draft](./frama-c-eacsl-format-promoted-argument-signedness.md) | [issue](./filing/30-eacsl-format-promoted-argument-signedness-issue.md), filed [#2819](https://git.frama-c.com/pub/frama-c/-/work_items/2819) (partly a question on `int`/`unsigned`) | [MR](./filing/30-eacsl-format-promoted-argument-signedness-mr.md), opened [!48](https://git.frama-c.com/pub/frama-c/-/merge_requests/48) | [sh](./repro/30-eacsl-format-promoted-argument-signedness.sh) | [validated](./patches/30-eacsl-format-promoted-argument-signedness.patch) (static fix; no existing oracle changes) |
| 31 | E-ACSL | `--validate-format-strings`: `%s` after a `double` checks the wrong argument | [draft](./frama-c-eacsl-format-fp-argument-slots.md) | [issue](./filing/31-eacsl-format-fp-argument-slots-issue.md), filed [#2820](https://git.frama-c.com/pub/frama-c/-/work_items/2820) | [MR](./filing/31-eacsl-format-fp-argument-slots-mr.md), opened [!49](https://git.frama-c.com/pub/frama-c/-/merge_requests/49) | [sh](./repro/31-eacsl-format-fp-argument-slots.sh) | [validated](./patches/31-eacsl-format-fp-argument-slots.patch) |
| 32 | E-ACSL | `--validate-format-strings`: a `*` width or precision shifts every later argument check | [draft](./frama-c-eacsl-format-star-width-precision.md) | [issue](./filing/32-eacsl-format-star-width-precision-issue.md), filed [#2822](https://git.frama-c.com/pub/frama-c/-/work_items/2822) | [MR](./filing/32-eacsl-format-star-width-precision-mr.md), opened [!50](https://git.frama-c.com/pub/frama-c/-/merge_requests/50) | [sh](./repro/32-eacsl-format-star-width-precision.sh) | [validated](./patches/32-eacsl-format-star-width-precision.patch) (runtime only; stacks with 30 and 31 in any order; numbered `*` not covered) |
| 33 | E-ACSL | `--validate-format-strings` without `-M`: every call with a literal format aborts | [draft](./frama-c-eacsl-format-literal-without-full-mtracking.md) | [issue](./filing/33-eacsl-format-literal-without-full-mtracking-issue.md), filed [#2821](https://git.frama-c.com/pub/frama-c/-/work_items/2821) (upstream's private e-acsl#118) | [MR](./filing/33-eacsl-format-literal-without-full-mtracking-mr.md), opened [!51](https://git.frama-c.com/pub/frama-c/-/merge_requests/51) | [sh](./repro/33-eacsl-format-literal-without-full-mtracking.sh) | [validated](./patches/33-eacsl-format-literal-without-full-mtracking.patch) (regenerates 3 existing `format/` oracles) |
| 34 | Libc / Kernel | GCC `__builtin_{add,sub,mul}_overflow`: wrong Eva result for mixed operand types, parse error for `char` operands, `_p` forms missing, uncompilable implicit declaration | [draft](./frama-c-kernel-gcc-overflow-builtins.md) | [issue](./filing/34-kernel-gcc-overflow-builtins-issue.md), filed [#2823](https://git.frama-c.com/pub/frama-c/-/work_items/2823) | none | [sh](./repro/34-kernel-gcc-overflow-builtins.sh) | none (the issue lists five options) |
| 35 | Kernel | `__restrict__` is a syntax error unless a Frama-C libc header is included | [draft](./frama-c-kernel-restrict-gnu-spelling.md) | [issue](./filing/35-kernel-restrict-gnu-spelling-issue.md), filed [#2824](https://git.frama-c.com/pub/frama-c/-/work_items/2824) | [MR](./filing/35-kernel-restrict-gnu-spelling-mr.md), opened [!52](https://git.frama-c.com/pub/frama-c/-/merge_requests/52) | [sh](./repro/35-kernel-restrict-gnu-spelling.sh) | [validated](./patches/35-kernel-restrict-gnu-spelling.patch) (one lexer line and a test) |
| 36 | E-ACSL | `--zone-sizes heap:2048` or `stack:2048`: every run crashes (`int` overflow of the size in bytes) | [draft](./frama-c-eacsl-heap-zone-size-overflow.md) | [issue](./filing/36-eacsl-heap-zone-size-overflow-issue.md), filed [#2825](https://git.frama-c.com/pub/frama-c/-/work_items/2825) | [MR](./filing/36-eacsl-heap-zone-size-overflow-mr.md), opened [!53](https://git.frama-c.com/pub/frama-c/-/merge_requests/53) | [sh](./repro/36-eacsl-heap-zone-size-overflow.sh) | [validated](./patches/36-eacsl-heap-zone-size-overflow.patch) |
| 37 | E-ACSL | bittree model: `pt_lookup` returns an uninitialized pointer (every `free` aborts); `int main(void)` crashes at exit | [draft](./frama-c-eacsl-bittree-lookup-uninitialized.md) | [issue](./filing/37-eacsl-bittree-lookup-uninitialized-issue.md), filed [#2826](https://git.frama-c.com/pub/frama-c/-/work_items/2826) | [MR](./filing/37-eacsl-bittree-lookup-uninitialized-mr.md), opened [!54](https://git.frama-c.com/pub/frama-c/-/merge_requests/54) | [sh](./repro/37-eacsl-bittree-lookup-uninitialized.sh) | [validated](./patches/37-eacsl-bittree-lookup-uninitialized.patch) |
| 38 | E-ACSL | bittree model: `stdin`, `stdout`, `stderr` and `errno` are not tracked | [draft](./frama-c-eacsl-bittree-standard-streams-untracked.md) | [issue](./filing/38-eacsl-bittree-standard-streams-untracked-issue.md), filed [#2827](https://git.frama-c.com/pub/frama-c/-/work_items/2827) | [MR](./filing/38-eacsl-bittree-standard-streams-untracked-mr.md), opened [!55](https://git.frama-c.com/pub/frama-c/-/merge_requests/55) | [sh](./repro/38-eacsl-bittree-standard-streams-untracked.sh) | [validated](./patches/38-eacsl-bittree-standard-streams-untracked.patch) (one line; complete under `-G clang` only with 37) |
| 39 | Libc | Linux `<sys/epoll.h>` and `<sys/inotify.h>` are missing (feature request) | [draft](./frama-c-libc-linux-header-gaps.md) | [issue](./filing/39-libc-linux-header-gaps-issue.md), filed [#2828](https://git.frama-c.com/pub/frama-c/-/work_items/2828) | [MR](./filing/39-libc-linux-header-gaps-mr.md), opened [!56](https://git.frama-c.com/pub/frama-c/-/merge_requests/56) | [sh](./repro/39-libc-linux-header-gaps.sh) | [validated](./patches/39-libc-linux-header-gaps.patch) (two headers with contracts, 10 files) |
| 40 | WP | `-wp-report-json` keeps one prover per goal (feature request); two errors in the manual | [draft](./frama-c-wp-report-per-prover-results.md) | [issue](./filing/40-wp-report-per-prover-results-issue.md), filed [#2829](https://git.frama-c.com/pub/frama-c/-/work_items/2829) | [MR](./filing/40-wp-report-per-prover-results-mr.md), opened [!57](https://git.frama-c.com/pub/frama-c/-/merge_requests/57) (manual only; does not close the issue) | [sh](./repro/40-wp-report-per-prover-results.sh) | [manual only](./patches/40-wp-report-per-prover-results.patch) (two sentences; lint run, manual not built) |
| 41 | Libc | `<sys/ioctl.h>`: `TIOCMGET`/`TIOCMSET` without the `TIOCM_*` modem-line bits | [draft](./frama-c-libc-ioctl-modem-bits.md) | [issue](./filing/41-libc-ioctl-modem-bits-issue.md), filed [#2830](https://git.frama-c.com/pub/frama-c/-/work_items/2830) | [MR](./filing/41-libc-ioctl-modem-bits-mr.md), opened [!58](https://git.frama-c.com/pub/frama-c/-/merge_requests/58) | [sh](./repro/41-libc-ioctl-modem-bits.sh) | [validated](./patches/41-libc-ioctl-modem-bits.patch) on `b80fcac74f` (eleven macros and a test, 3 files) |
| 42 | WP | Hexadecimal floating-point literals not read: `DBL_MAX` bound dropped, lemma stops WP, and `0x1.8p1f` read as 0 under `-wp-model +real` (**soundness**); `f32`/`f64` suffixes rejected | [draft](./frama-c-wp-hexadecimal-float-literals.md) | [issue](./filing/42-wp-hexadecimal-float-literals-issue.md), filed [#2831](https://git.frama-c.com/pub/frama-c/-/work_items/2831) | [MR](./filing/42-wp-hexadecimal-float-literals-mr.md), opened [!59](https://git.frama-c.com/pub/frama-c/-/merge_requests/59) | [sh](./repro/42-wp-hexadecimal-float-literals.sh) | [validated](./patches/42-wp-hexadecimal-float-literals.patch) on `b80fcac74f` (one function and a test, 6 files) |
| 43 | E-ACSL | Real constants that are not exactly a `double`: unexpected error with an exponent or in hexadecimal (`1e-9`), and a `long double` one (`0.1L`) is 0 at run time | [draft](./frama-c-eacsl-real-constant-notation.md) | [issue](./filing/43-eacsl-real-constant-notation-issue.md), **not filed** | [MR](./filing/43-eacsl-real-constant-notation-mr.md), **not opened** | [sh](./repro/43-eacsl-real-constant-notation.sh) | [validated](./patches/43-eacsl-real-constant-notation.patch) on `b80fcac74f` (one function and a test, 5 files) |
| 44 | Libc | `strlcat`: the result is stated against `dest` after the call, and `assigns` covers a byte past `n`; Eva gives a wrong result without an alarm, WP proves a false postcondition (**soundness**) | [draft](./frama-c-libc-strlcat-contract.md) | [issue](./filing/44-libc-strlcat-contract-issue.md), **not filed** | [MR](./filing/44-libc-strlcat-contract-mr.md), **not opened** | [sh](./repro/44-libc-strlcat-contract.sh) | [validated](./patches/44-libc-strlcat-contract.patch) on `b80fcac74f` (four clauses and a test, 4 files) |
| 45 | MetAcsl | `\result` is refused in a `\postcond` property (`\result meaningless`); under `\tguard` it collapses to `\true` | [draft](./frama-c-metacsl-result-in-postcond.md) | [issue](./filing/45-metacsl-result-in-postcond-issue.md), **not filed** (pub/meta; listed in #2832) | [MR](./filing/45-metacsl-result-in-postcond-mr.md), **not opened** | [sh](./repro/45-metacsl-result-in-postcond.sh) | [built](./patches/45-metacsl-result-in-postcond.patch) on pub/meta `4f43801390` (`meta_parse.ml`, doc and a test) |
| 46 | Libc | `<sched.h>`: no `cpu_set_t`, `CPU_*` macros or `sched_setaffinity`/`sched_getaffinity` under `_GNU_SOURCE` | [draft](./frama-c-libc-sched-cpu-set.md) | [issue](./filing/46-libc-sched-cpu-set-issue.md), **not filed** (listed in #2832) | none | [c](./repro/46-libc-sched-cpu-set.c) | none |
| 47 | MetAcsl | Callee `Old`/`Pre`/`Here` labels copied into `\written`/`\read` instances at a call: `Old` aborts E-ACSL and WP, `Pre` and `Here` (under `After`) let WP prove false properties (**soundness**) | [draft](./frama-c-metacsl-callee-old-label-in-written.md) | [issue](./filing/47-metacsl-callee-old-label-in-written-issue.md), **not filed** (pub/meta; listed in #2832) | [MR](./filing/47-metacsl-callee-old-label-in-written-mr.md), **not opened** | [sh](./repro/47-metacsl-callee-old-label-in-written.sh) | [built](./patches/47-metacsl-callee-old-label-in-written.patch) on pub/meta `4f43801390` (one visitor and a test) |
| 48 | MetAcsl | `-meta-fold`: folded instances have no location (`<unknown>:0` under E-ACSL) | [draft](./frama-c-metacsl-fold-annotation-location.md) | [issue](./filing/48-metacsl-fold-annotation-location-issue.md), **not filed** (pub/meta; listed in #2832) | [MR](./filing/48-metacsl-fold-annotation-location-mr.md), **not opened** | [sh](./repro/48-metacsl-fold-annotation-location.sh) | [built](./patches/48-metacsl-fold-annotation-location.patch) on pub/meta `4f43801390` (locations passed, new test + one oracle) |
| 49 | MetAcsl | Feature: a call to a function without specification gets no `\writing`/`\reading` instance and no warning (libc under `e-acsl-gcc`); `\written`/`\read` terms lack locations (`<unknown>:0` E-ACSL guards) | [draft](./frama-c-metacsl-eacsl-libc-instances.md) | [issue](./filing/49-metacsl-eacsl-libc-instances-issue.md), **not filed** (pub/meta; listed in #2832) | [MR](./filing/49-metacsl-eacsl-libc-instances-mr.md), **not opened** | [sh](./repro/49-metacsl-eacsl-libc-instances.sh) | [built](./patches/49-metacsl-eacsl-libc-instances.patch) on pub/meta `4f43801390` (warning only) |
| 50 | E-ACSL | `--validate-format-strings`: `Assertion failed` in `functions.ml:156` on `enum` arguments and `Options.fatal` on `enum *` pointers | [draft](./frama-c-eacsl-format-enum-argument.md) | [issue](./filing/50-eacsl-format-enum-argument-issue.md), **not filed** (staged for #2832) | [MR](./filing/50-eacsl-format-enum-argument-mr.md), **not opened** | [sh](./repro/50-eacsl-format-enum-argument.sh) | [validated](./patches/50-eacsl-format-enum-argument.patch) on `189053d4a2` (`functions.ml` + `printf_enum.c`, 5 files; stacks with !48) |

Not filed, by decision (see the catalog): Issues 2, 6, 7 and 11. 43 to 50 wait for the owner's
go-ahead.

## How to file

1. **Issue first.** Open the issue from `filing/NN-*-issue.md`: the first line (without `# `) is the
   title, and everything below the HTML comment is the description.
2. **Order where texts reference each other:**
   - 23 and 27 cite each other: done (27 filed first, then 23, then 27's description edited).
   - 12 before 10.
   - 8 and 13 can go together.
   - 30 to 33: the MR texts of 32 and 33 cite the issues of 30 and 31 (and 33's cites 32's), and
     32's issue cites 33's. File the four issues before filling in any of these texts.
   - 37 before 38: 38's issue and MR cite 37's issue (`#<issue-37>`).
3. **Replace the placeholders** with the real numbers: `#<issue>`, `#<issue-37>` and `#ISSUE-NN` in
   the texts, and `!<MR>` in MR 10.
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

28 to 40 were filed on 2026-11-18 with the option each row calls "current"; their rows stay as
points the maintainers may raise, and are no longer blocking. 41 and 42 were filed the same day.
43 and 44 are drafted and wait for the owner.

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
| 29 | Keep the impact counts (minmea 371/372, nettle 15/24) in the issue? Keep the `\object_pointer(stdin)` case in the test? The MR's closing note describes two bittree defects that are now packages 37 and 38; as filed, it cites #2826 and #2827. |
| 30 | `_Bool` reuses the letter `C`, so a rejected `_Bool` is named `'unsigned char'`; a new letter would shift 85 lines of the `printf.c` dev oracle. |
| 30 / 31 | The MR texts reference each other's issue (#2819 and #2820 since the filing of 2026-11-18). 31's issue notes the cosmetic `%n` message ("argument 1" for directive 2) without fixing it. |
| 30 / 31 / 32 | Three merge requests (current; they apply in any order and pass together), or one for the three format fixes? |
| 32 | Offer a follow-up for POSIX numbered `*` arguments (`%2$*1$d`), which the patch leaves unchecked? |
| 33 | File it although upstream tracks it privately as e-acsl#118? The issue text says so. Its patch regenerates three existing oracles (`gen_printf.0.c` alone: 3,297 lines added, 547 removed); land it after 30 to 32, or let whichever lands second regenerate the `gen_*.0.c` of the other tests? |
| 34 | One issue (current), or two: the kernel part (an implicit declaration printed as C that no compiler accepts) and the libc part (the `_Generic` model)? No patch is proposed; the issue lists five options. |
| 35 | Also remove the now redundant `#define __restrict__ __restrict` from `share/libc/features.h`? |
| 36 | Make `--zone-sizes tls:N` work, or document that it does nothing? `PGM_TLS_SIZE` is never read; the patch leaves it. |
| 37 / 38 | Is the bittree model still supported upstream? Every `free` has aborted there since 25.0, and the manual recommends the model for targets other than x86-64. Its other defects are listed under "Seen during the audit, not drafted". |
| 39 | Keep the packed attribute on `struct epoll_event` (Frama-C then warns `addr-of-packed-field`)? Report `pipe2`, `dup3` and `accept4` (POSIX.1-2024) as a separate issue? |
| 40 | Decided on 2026-11-18: the issue keeps the feature request and names the two manual errors, and a manual-only merge request (!57) corrects them. |
| 41 | Decided on 2026-11-18: a new issue with its merge request, not a note on #2828. Still open for the maintainers: eleven names, as glibc's `<sys/ioctl.h>` (as filed), or also the three Linux-only ones (`TIOCM_OUT1`, `TIOCM_OUT2`, `TIOCM_LOOP`)? Both texts offer the three. |
| 42 | Filed on 2026-11-18 as one issue for the three symptoms. Still open for the maintainers: the wrong proof under `-wp-model +real` on its own issue? A `plugins/wp/Changelog` entry? The patch has none, as 19's. |
| 43 | File it? If so: one issue for the two symptoms (current), or the silent 0 of `0.1L` on its own? Report a suffixed constant as not yet supported (current), or give it the value of the target's `long double`? A `plugins/e-acsl/doc/Changelog` entry? The patch has none. |
| 44 | File it? Decided on 2026-11-18: the patch also strengthens the `separation` precondition to `src+(0..strlen(src))` (measured: no oracle of `tests/libc` or of the E-ACSL suite changes with it; both texts say it can be dropped). Rename the check `imprecise` of `tests/libc/string_h.c`, which becomes valid? |
| 45 | File it on `pub/meta` (issue and validated MR are ready, still paused)? Stacks cleanly with 47 to 49 (only `CHANGELOG.md` conflicts). `file_upstream.py` knows project 780 only, so it is filed by hand. |
| 47 to 49 | File them on `pub/meta` (issues and MRs)? 49 cites 47 and 48, so file those first and replace `#ISSUE-47` and `#ISSUE-48`. Listed in #2832 since 2026-11-20. `file_upstream.py` knows project 780 only, so they are filed by hand. |
| 50 | File it on `pub/frama-c` once the filing pause lifts, or fold it into a combined format-validation MR with `!48`, `!49` and `!50` if the maintainers answer question 3 of `#2832` in favour of combining them? Stacks cleanly with `!48` in either order. |
| hunt | Which of the candidates of [`./frama-c-hunt-2026-11-18-candidates.md`](./frama-c-hunt-2026-11-18-candidates.md) to turn into packages, and in which order? That document ranks them ("Order of criticity"); N1 (enumeration constants), L2 (`pclose`) and L1 (`void` objects under WP) come first. N1 reverts a deliberate upstream change, so it needs the argument from C11 and gcc. |

## Identified, not filed

Each of these is worked around or documented in the pipeline. None is a defect to report as a bug:

| Item | Where | Why not filed |
| :-- | :-- | :-- |
| Issues 2, 6, 7, 11 | [catalog](./frama-c-e-acsl-issues.md) | Documented behaviour, deliberate convention, or changelog notes |
| E-ACSL resets `__e_acsl_sound_verdict` after `strto*`/`wcsto*` calls | `scripts/eacsl_toolchain.py` `rewrite_sound_verdict_resets` | By design: no model for those functions, so later verdicts are marked unsound |
| E-ACSL ignores a quantifier without an upper bound | [`../../troubleshooting/eacsl-and-fuzzing.md`](../../troubleshooting/eacsl-and-fuzzing.md) | Documented limitation (warning "Missing upper bound") |
| E-ACSL rejects pointers from uninstrumented libraries | same | Inherent to shadow memory |
| WP `Typed`: casts between pointer types, unions | [`../../troubleshooting/wp-and-guardrail.md`](../../troubleshooting/wp-and-guardrail.md) | Documented memory-model limitation; the pipeline uses `Bytes` |
| WP `Typed`: `lsl` missing upper-bound and symbolic-shift lemmas (`byte << N`, `1 << shift`) | [`../../troubleshooting/wp-and-guardrail.md`](../../troubleshooting/wp-and-guardrail.md) | Prover/Why3 theory completeness limitation, not a bug |
| WP: no framing stub for variadic callees | [`../../troubleshooting/harnesses-and-seeds.md`](../../troubleshooting/harnesses-and-seeds.md) | Documented limitation |
| WP: `ioctl` (`__va_ioctl_ptr` assigns `((char *)argp)[0..]`) aborts WP with `Invalid infinite range` when a contract names another location | [`../../troubleshooting/wp-and-guardrail.md`](../../troubleshooting/wp-and-guardrail.md) | Same unbounded-range family as #2798/#2799, but `ioctl`'s written size depends on the request code; needs a request-specific stub |
| Frama-C libc missing headers and declarations (`<netinet/ip_icmp.h>`, glibc `__int8_t` aliases, Linux declarations) | `templates/fc_stubs/` | Coverage gaps, not wrong contracts. `sys/epoll.h` and `sys/inotify.h` are now package 39, whose issue lists the other Linux gaps and asks which are wanted |

## Seen during the audit, not drafted

- **Other defects of the E-ACSL bittree model** (seen on 2026-11-17 while drafting 37 and 38; the
  first two fail in upstream's `memory/` suite run with `--memory-model bittree`, the rest were
  read in the source and not run):
  - a `__attribute__((constructor))` that allocates crashes (`memory/constructor.c`);
  - `\initialized` on a range past the end of a block is true (`memory/ranges_in_builtins.c:65`);
  - `free` seems not to release the `bt_block`;
  - `eacsl_make_memory_spaces(MB_SZ(64), MB_SZ(64))` evaluates to 0 and 0;
  - `eacsl_memory_init` is not run-once.
- **`e-acsl-gcc --zone-sizes tls:N` has no effect** (`PGM_TLS_SIZE` is never read), and
  `e-acsl-gcc:381` spells a variable `OPTIONS_TLS_SIZE`. Noted in package 36, not fixed.
- **`--validate-format-strings` does not check POSIX numbered `*` arguments** (`%2$*1$d`). Noted in
  package 32, not fixed.
- **Dead branch in `e_acsl_temporal.c`.** `eacsl_temporal_save_return` tests a comma expression,
  which is always true. Noted in
  [`./frama-c-eacsl-temporal-function-address-argument.md`](./frama-c-eacsl-temporal-function-address-argument.md).
- **Cosmetic wrong names in E-ACSL libc-replacement diagnostics:** `memmove` reports "memcmp",
  `strcpy` reports "strlen" and `strncat` reports "strcat". Mentioned in issue 17 as a follow-up.
- **Kernel accepts `sizeof x` on an incomplete struct** in a file-scope initializer. Seen while
  probing `ip_mreqn`; not confirmed.
- **E-ACSL crashes on a real literal with an exponent** (seen on 2026-11-18, looking for siblings
  of 42): now package 43, see the coverage table.
- **The hunt of 2026-11-18** (siblings of 42 and 43, by four subagents and the parent session,
  then a second opinion by six reviewers): candidates, none drafted, in
  [`./frama-c-hunt-2026-11-18-candidates.md`](./frama-c-hunt-2026-11-18-candidates.md). Among
  them, the three defects that 43's draft names: floating-point constants printed with 12
  significant digits, a rational cast to `double` by truncation, and `inf` printed as a C
  constant.
- **E-ACSL aborts with `labels pre-analysis was not performed on construct \old(idx)` on ranged
  `ensures \initialized(dest + (idx .. idx + n))`** (seen on libmodbus run-1, 2026-11-18,
  [`../../troubleshooting/wp-and-guardrail.md`](../../troubleshooting/wp-and-guardrail.md)).
  Reproduced on 2026-11-20 in `framac-analysis:latest` (`34.0~beta`) with a 9-line reproducer
  (`e-acsl-gcc -c` internal error); no duplicate on `pub/frama-c` (live search returned only our
  #2800 for `<==>`). Not yet tested on `master` (no `framac-master-audit` image on disk), not
  drafted, and not listed in #2832.
- **WP tail-call `return strerror(errnum)` `assigns` sub-goal** (`modbus_strerror`, seen on
  libmodbus run-1, 2026-11-18,
  [`../../troubleshooting/wp-and-guardrail.md`](../../troubleshooting/wp-and-guardrail.md)). A
  minimal standalone `/*@ assigns \nothing; */ const char *my_str(int e) { return strerror(e); }`
  did not reproduce on `34.0~beta` (5/5 goals proved by Qed); needs extraction of a standalone
  reproducer from `libmodbus`'s `modbus_strerror` before drafting or adding to #2832.

Drafted since this list was written: the bittree crash on `int main(void)` is package 37, and the
literal format string rejected without `-M` is package 33.
