# Kernel (`Cil_printer`): `__int128` Constants Printed with `LL`/`ULL` Suffix Are Truncated by GCC/Clang and Rejected on Re-Parse

- **Parent index:** [`./README.md`](./README.md)
- **Filing issue:** [`./filing/79-kernel-int128-const-printing-issue.md`](./filing/79-kernel-int128-const-printing-issue.md)
- **Filing MR:** [`./filing/79-kernel-int128-const-printing-mr.md`](./filing/79-kernel-int128-const-printing-mr.md)
- **Standalone reproducer:** [`./repro/79-kernel-int128-const-printing.sh`](./repro/79-kernel-int128-const-printing.sh) + [`./repro/79-kernel-int128-const-printing.c`](./repro/79-kernel-int128-const-printing.c)
- **Patch:** [`./patches/79-kernel-int128-const-printing.patch`](./patches/79-kernel-int128-const-printing.patch)
- **Hunt origin:** Candidate `N5` in [`./frama-c-hunt-2026-11-18-candidates.md`](./frama-c-hunt-2026-11-18-candidates.md)

## 1. Summary

`Cil_printer.constant` (`src/kernel/services/ast_printing/cil_printer.ml:627-628`) prints `IInt128`
constants with `LL` and `IUInt128` constants with `ULL`. Neither ISO C nor GCC/Clang supports
128-bit integer literal suffixes. Whenever `-constfold` (enabled by default in `e-acsl-gcc`)
synthesizes a 128-bit constant outside 64-bit range (e.g. `((__int128)1 << 100) + 5`,
`~(unsigned __int128)0`, `INT128_MIN`), Frama-C emits out-of-range `LL`/`ULL` literals:

- GCC silently truncates them to 64 bits with only a warning (`integer constant is too large for
  its type`), causing both compiled `-print -ocode` output and `e-acsl-gcc` instrumented binaries
  to compute wrong values.
- Clang rejects the literals outright as compile errors.
- Frama-C itself aborts when re-parsing its own output (`User Error: Cannot represent the integer
  1267650600228229401496703205381LL`, exit 1).

## 2. Duplicate Check

Live read-only `glab api` search against `pub/frama-c` (project 780, issues and MRs, all states,
2026-11-22) for `IInt128`, `__int128`, `128-bit`, plus
[`./pub-frama-c_work_items_2026-11-09.csv`](./pub-frama-c_work_items_2026-11-09.csv) and packages
`01`-`50`: **0 duplicates** (open `#2641` is about parsing `__int128` without a GCC machdep;
`#2823` is GCC overflow builtins; `#2832` overview).

## 3. Fix & Validation

In `src/kernel/services/ast_printing/cil_printer.ml`, add `pretty_int128_constant`:

- When an `IInt128` or `IUInt128` constant fits in 64-bit `ILongLong` / `IULongLong`, print
  `(__int128)<lit>` or `(unsigned __int128)<lit>` using `pretty_C_constant`.
- Otherwise, extract two's-complement 64-bit unsigned high and low halves via `Z.extract i 64 64`
  and `Z.extract i 0 64`, emitting `(((unsigned __int128)0x<hi>ULL << 64) | 0x<lo>ULL)` (omitting
  `| 0x0ULL` when the low half is 0), wrapped in `((__int128)...)` for signed `IInt128`.
- Add regression test `tests/pretty_printing/int128_const.c`.

### Validation Log

- **Before (`master` `189053d4a2` and `34.0~beta`, stock images):** Reproducer `79` fails 4 of 4
  cases identically on both versions (`int128_gcc` and `int128_eacsl` silently truncate all four
  >64-bit constants to 64 bits; `int128_clang` fails to compile; `int128_reparse` fails with
  `Cannot represent the integer`).
- **After (`master` `189053d4a2` + patch `79`, commit `0ebfb11231`):**
  - Reproducer `79`: `RESULT: fixed` (4/4 cases pass with zero GCC/Clang warnings).
  - Regression test `tests/pretty_printing/int128_const.c` fails on unpatched `master` (`Cannot
    represent the integer`, exit 1) and passes patched.
  - Default test suites: `tests/pretty_printing`, `tests/syntax`, and `plugins/e-acsl` all pass
    (with 2 expected lines updated in `plugins/e-acsl/tests/constructs/oracle/gen_typedef.0.c`).
  - **4-way stacking (`cil_printer.ml`):** `20` (`!43`) + `51` + `78` + `79` and reverse
    `79` + `78` + `51` + `20` both apply cleanly via `git am --3way --keep-non-patch`, build, and
    pass `tests/pretty_printing` and `plugins/e-acsl`.
  - `./dev/check-files.sh -p HEAD~1`: passes (`Lint 4 file(s)`), 0 file-mode changes.
- **Pipeline / `opam/` recommendation:** Low priority (pipeline passes `--no-constfold`).
