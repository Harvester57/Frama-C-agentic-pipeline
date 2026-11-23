# Kernel: Enumeration constants of non-negative enums are typed unsigned (`enum.ekind`) instead of `int` (`#@1682` regression)

Draft for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).
**Not filed (issue-only, no patch).** Issue 63 of this folder, drafted on 2026-11-23 (hunt
candidate `N1`). Filing remains paused pending the maintainers' reply on
[#2832](https://git.frama-c.com/pub/frama-c/-/work_items/2832).

**Package:**
[issue text](./filing/63-kernel-enum-const-unsigned-type-issue.md),
[reproducer](./repro/63-kernel-enum-const-unsigned-type.sh) with its
[C file](./repro/63-kernel-enum-const-unsigned-type.c).
No patch or merge request is drafted because commit `2da90c219f` (`#@1682`, merged `7e9af986e2`)
was a deliberate upstream change touching 121 files and awaits maintainer direction on `#2832`.

## Summary

For any enumeration whose constants are all non-negative and fit in `int` (for example
`enum { N = 4 };`), Frama-C types each enumeration constant as `unsigned int` (`enum.ekind`) rather
than `int`. In signed comparisons such as `int i = -1; if (i < N)`, C usual arithmetic conversions
promote `i` to `unsigned int`, turning `i < N` into `(unsigned int)i < N` (`0` instead of `1`).

Under `-machdep gcc_x86_64`, this causes unsound results across all three analyses:

- **WP (`-wp -wp-rte`):** proves all `4 / 4` goals on `if (i < N) return a[i];`, proving an
  out-of-bounds read `a[-1]` safe; proves false postcondition `ensures \result == 0` for
  `i = -1; return i < MAX;`.
- **Eva (`-eva`):** evaluates `i < MAX` to `0` (`__retres ∈ {0}`), marks true check `c_int_ok`
  invalid, and treats `for (int i = -1; i < MAX; i++)` as zero iterations.
- **E-ACSL:** prints `(unsigned int)i < N` into the instrumented C code, so the monitored binary
  takes the opposite branch and misses the out-of-bounds read.

## Versions

| | Result |
| :-- | :-- |
| `34.0~beta (Selenium)`, opam build (`framac-analysis:latest`, 2026-11-23) | **reproduces** (`RESULT: bug present (4 of 4 checks fail)`) |
| `35.0~~dev (Bromine)`, `master` `189053d4a2` (`framac-master-audit:189053d`, 2026-11-23) | **reproduces**, identical output (`RESULT: bug present (4 of 4 checks fail)`) |

Debian GNU/Linux 13 (trixie; glibc 2.41, gcc 14.2.0).

## Standards and GCC 14.2.0 verification

- **ISO C11/C17 6.7.2.2p3:** "The identifiers in an enumerator list are declared as constants that
  have type `int` and may appear wherever such are permitted."
- **ISO C23 6.7.2.2p12:** "If all values of all enumeration constants can be represented as an
  `int`, each enumeration constant has type `int`; otherwise, each enumeration constant has the
  same type as the enumerated type."
- **GCC 14.2.0** (verified live under `-std=c11`, `-std=gnu11`, `-std=c23`, and `-fshort-enums`):
  - `enum E_fit { A = 0, B = 1 }`: `enum E_fit` is `unsigned int` (or `unsigned char` with
    `-fshort-enums`), while `A` and `B` have type **`int`**. `(-1) < B` is `1`, while
    `((enum E_fit)-1) < B` is `0`.
  - `enum E_u32 { C = 0, D = 0x80000000U }` (like `secbool` in `#@1682`): because `D > INT_MAX`,
    GCC types both `C` and `D` as **`unsigned int`** (`ekind`).
  - `enum E_i64 { E = 0, F = 0x100000000LL }`: GCC types both `E` and `F` as **`unsigned long`**.

## Root cause

`src/kernel/internals/typing/cabs2cil.ml:4395-4408` (commit `2da90c219f` / MR `!5657`, merged
`7e9af986e2` on 2026-04-10, `Changelog` line 139: `Fix enumeration typing by making sure all items
are of type ekind (#@1682)`) casts every `enum.eitems` element unconditionally to `enum.ekind`, and
`cabs2cil.ml:5538-5543` (`EnvEnum item`) uses `Cil.typeOf item.eival` as the expression type.

In `tests/syntax/enum_typing_issue_1682.i`, `secbool` (`0x55aa55aa`, `0xaa55aa55`) genuinely needs
`ekind` (`unsigned int`) because `0xaa55aa55 > INT_MAX`, whereas `loglevel` (`NONE = 0, FATAL = 1`)
fits in `int` and must keep `int` constants under C11/C23/GCC.

`-enums int` is not a sound workaround because it sets `enum.ekind = IInt`, breaking
`enum Small sv = (enum Small)-1; sv < S1` (Eva evaluates it to `1`; GCC evaluates it to `0`).

## Duplicate search

Searched `pub/frama-c` (project 780, issues and MRs, all states, live read-only `glab api` on
2026-11-23), `pub-frama-c_work_items_2026-11-09.csv`, and packages `01`–`50` for
`enumeration constant`, `enum unsigned`, `ekind`, `1682`, `gcc-enums`, `enum item`: zero public
duplicates (`#@1682` is private; `#2832` overview lists `N1` as a maintainer question).

## Local `opam/` patch queue recommendation

**NO** (issue-only upstream; do not patch locally without upstream consensus, as reverting or
restricting `#@1682` alters AST typing across enum-heavy targets and 100+ upstream oracles).
