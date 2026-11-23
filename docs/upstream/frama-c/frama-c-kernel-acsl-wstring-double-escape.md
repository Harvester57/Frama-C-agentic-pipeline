# Kernel (`Cil_printer`): ACSL Wide-String Printer (`LWStr`) Double-Escapes Characters via `%S` and Prints Empty `L""` as Bare `L`

- **Parent index:** [`./README.md`](./README.md)
- **Filing issue:** [`./filing/78-kernel-acsl-wstring-double-escape-issue.md`](./filing/78-kernel-acsl-wstring-double-escape-issue.md)
- **Filing MR:** [`./filing/78-kernel-acsl-wstring-double-escape-mr.md`](./filing/78-kernel-acsl-wstring-double-escape-mr.md)
- **Standalone reproducer:** [`./repro/78-kernel-acsl-wstring-double-escape.sh`](./repro/78-kernel-acsl-wstring-double-escape.sh) + [`./repro/78-kernel-acsl-wstring-double-escape.c`](./repro/78-kernel-acsl-wstring-double-escape.c)
- **Patch:** [`./patches/78-kernel-acsl-wstring-double-escape.patch`](./patches/78-kernel-acsl-wstring-double-escape.patch)
- **Hunt origin:** Candidate `N12` in [`./frama-c-hunt-2026-11-18-candidates.md`](./frama-c-hunt-2026-11-18-candidates.md)

## 1. Summary

In `src/kernel/services/ast_printing/cil_printer.ml:2399-2413` (`Cil_printer.logic_constant`), the
`LWStr` case has two bugs:

1. **Double-escaping (lines 2406-2407):** Formats `Escape.escape_char (Char.chr (Int64.to_int elt))`
   with `%S`, escaping every backslash and quote a second time (`L"\n\t"` becomes `L"\\n" "\\t" `,
   `L"a\"b"` becomes `L"a" "\\\"" "b" `, `L"\351"` becomes `L"\\351" `). Re-parsing turns valid
   `sizeof` checks into invalid checks under Eva and `Prove: false.` under WP.
2. **Empty wide string `L""` prints bare `L` (lines 2401-2411):** For `LWStr []`, `List.iter`
   emits nothing after `L`, printing `sizeof(L)` which fails re-parsing with
   `[kernel:annot-error] unbound logic variable L` (exit 1).

## 2. Duplicate Check

Live read-only `glab api` search against `pub/frama-c` (project 780, issues and MRs, all states,
2026-11-22) for `LWStr`, `wide string`, plus
[`./pub-frama-c_work_items_2026-11-09.csv`](./pub-frama-c_work_items_2026-11-09.csv) and packages
`01`-`50`: **0 duplicates**.

## 3. Fix & Validation

In `src/kernel/services/ast_printing/cil_printer.ml:2399-2411`, add `| LWStr [] -> fprintf fmt "L\"\""`
and replace `"%S"` with `"\"%s\""` (matching `LStr` at line 2398). Add regression test
`tests/pretty_printing/acsl_wstring.c`. Completely disjoint from `20`/`!43` (lines 1893-2195),
`51` (line 640), and `79` (lines 165, 618-636).

### Validation Log

- **Before (`master` `189053d4a2` and `34.0~beta`, stock images):** Reproducer `78` fails 3 of 3
  cases identically on both versions (`invalid=5` under Eva, `true=2, false=5` under WP,
  `unbound logic variable L` on `L""`).
- **After (`master` `189053d4a2` + patch `78`, commit `31e09e87d5`):**
  - Reproducer `78`: `RESULT: fixed` (3/3 cases pass: `esc_reparse_eva` `invalid=0`,
    `esc_reparse_wp` `true=7, false=0`, `empty_reparse_eva` `invalid=0`).
  - Regression test `tests/pretty_printing/acsl_wstring.c` fails on unpatched `master` (`unbound
    logic variable L`, exit 1, and double-escaped strings) and passes patched.
  - Default test suites: `tests/pretty_printing`, `tests/spec`, and `plugins/e-acsl` all pass
    with 0 existing oracle diffs.
  - `./dev/check-files.sh -p HEAD~1`: passes (`Lint 3 file(s)`), 0 file-mode changes.
- **Pipeline / `opam/` recommendation:** Low priority (ACSL wide strings only).
