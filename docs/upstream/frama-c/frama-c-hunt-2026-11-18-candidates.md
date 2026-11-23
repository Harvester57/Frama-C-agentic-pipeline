# Candidates from the hunt of 2026-11-18 (processed into packages 51–87 + private H13, not filed)

- **Parent index:** [`./README.md`](./README.md)

> [!NOTE]
> **Processed on 2026-11-23 (not filed; filing remains paused pending `#2832`).** Every candidate
> below was independently vetted on stock `framac-master-audit:189053d` (`35.0~~dev`, `189053d4a2`)
> and stock `framac-analysis:latest` (`34.0~beta`) and processed into 37 validated packages
> (`51`–`87`: 36 with validated single-commit patches + issue-only `63` for `N1`) plus 1 private
> internal analysis draft (`H13`, no `filing/` text). See [Processing disposition (2026-11-23)](#processing-disposition-2026-11-23) below.

After 42 (WP reads the text of a floating-point literal with its own, narrower parser), the owner
asked which related families of bugs could be hunted in Frama-C. This file lists what the hunt
found. One find became package 43
([`./frama-c-eacsl-real-constant-notation.md`](./frama-c-eacsl-real-constant-notation.md)). The
rest are mapped to their 2026-11-23 dispositions below.

## Processing disposition (2026-11-23)

| Candidate | Disposition | Package / Draft | `opam/` queue |
| :-- | :-- | :-- | :-- |
| `H1` | Confirmed TP — package + patch | `65`: [`./frama-c-wp-floor-ceil-truncate-float-cast.md`](./frama-c-wp-floor-ceil-truncate-float-cast.md) | **YES** |
| `H2` | Confirmed TP — package + patch | `67`: [`./frama-c-wp-float-constant-double-rounding.md`](./frama-c-wp-float-constant-double-rounding.md) | NO |
| `H3` | Confirmed TP — merged with `N2` | `66`: [`./frama-c-wp-empty-range-addition-shift.md`](./frama-c-wp-empty-range-addition-shift.md) | **YES** |
| `H4` | Confirmed TP — package + patch | `56`: [`./frama-c-kernel-float-cast-dropped-exact.md`](./frama-c-kernel-float-cast-dropped-exact.md) | **YES** |
| `H5` | Confirmed TP — package + patch | `61`: [`./frama-c-kernel-char-const-unsigned-machdep.md`](./frama-c-kernel-char-const-unsigned-machdep.md) | NO |
| `H6` | Confirmed TP — merged with `H18` | `59`: [`./frama-c-kernel-acsl-hex-octal-escapes.md`](./frama-c-kernel-acsl-hex-octal-escapes.md) | **YES** |
| `H7` | Confirmed TP — package + patch | `58`: [`./frama-c-kernel-acsl-string-sizeof-escaped.md`](./frama-c-kernel-acsl-string-sizeof-escaped.md) | **YES** |
| `H8` | Confirmed TP — package + patch | `62`: [`./frama-c-kernel-multichar-const-type.md`](./frama-c-kernel-multichar-const-type.md) | NO |
| `H9` | Skipped (not a wrong result) | — | NO |
| `H10` | Confirmed TP — merged with `N4` | `51`: [`./frama-c-kernel-float-const-printing.md`](./frama-c-kernel-float-const-printing.md) | **YES** |
| `H11` | Confirmed TP — package + patch | `52`: [`./frama-c-eacsl-rational-cast-double-rounding.md`](./frama-c-eacsl-rational-cast-double-rounding.md) | **YES** |
| `H12` | Confirmed TP — merged with `N14` | `77`: [`./frama-c-kernel-wstring-escape-trigraph.md`](./frama-c-kernel-wstring-escape-trigraph.md) | NO |
| `H13` | Confirmed TP — **private internal draft only** | Private: [`./frama-c-kernel-compilation-db-quoting.md`](./frama-c-kernel-compilation-db-quoting.md) | NO |
| `H14` | Confirmed TP — package + patch | `55`: [`./frama-c-eva-numerors-float-literal-parsing.md`](./frama-c-eva-numerors-float-literal-parsing.md) | NO |
| `H15` | Confirmed TP — package + patch (separate from `51`) | `53`: [`./frama-c-eacsl-non-finite-real-constant.md`](./frama-c-eacsl-non-finite-real-constant.md) | Optional / low |
| `H16` | Confirmed TP — package + patch | `69`: [`./frama-c-wp-strategy-timeout-exception.md`](./frama-c-wp-strategy-timeout-exception.md) | NO |
| `H17` | Confirmed TP — package + patch | `70`: [`./frama-c-wp-time-margin-validation.md`](./frama-c-wp-time-margin-validation.md) | NO |
| `H18` | Merged into `59` (`H6+H18`) | `59`: [`./frama-c-kernel-acsl-hex-octal-escapes.md`](./frama-c-kernel-acsl-hex-octal-escapes.md) | **YES** |
| `H19` | Skipped (documented `+real` limit) | — | NO |
| `L1` | Confirmed TP — package + patch | `64`: [`./frama-c-wp-void-object-size.md`](./frama-c-wp-void-object-size.md) | **YES** |
| `L2` | Confirmed TP — package + patch | `72`: [`./frama-c-libc-pclose-pipe-status-soundness.md`](./frama-c-libc-pclose-pipe-status-soundness.md) | **YES** |
| `L3` | Confirmed TP — package + patch | `73`: [`./frama-c-libc-sigaction-oldact-contract.md`](./frama-c-libc-sigaction-oldact-contract.md) | **YES** |
| `L4` | Confirmed TP — package + patch (distinct from `#2806`/`!37`) | `54`: [`./frama-c-eacsl-typing-not-performed-guard.md`](./frama-c-eacsl-typing-not-performed-guard.md) | **YES** |
| `L5` | Confirmed TP — package + patch | `75`: [`./frama-c-libc-syslog-string-axiomatic.md`](./frama-c-libc-syslog-string-axiomatic.md) | **YES** |
| `L6` | Skipped (cosmetic) | — | NO |
| `N1` | Confirmed TP — **issue-only** (`#@1682` regression) | `63`: [`./frama-c-kernel-enum-const-unsigned-type.md`](./frama-c-kernel-enum-const-unsigned-type.md) | NO |
| `N2` | Merged into `66` (`H3+N2`) | `66`: [`./frama-c-wp-empty-range-addition-shift.md`](./frama-c-wp-empty-range-addition-shift.md) | **YES** |
| `N3` | Confirmed TP — package + patch | `68`: [`./frama-c-wp-non-finite-float-constant.md`](./frama-c-wp-non-finite-float-constant.md) | **YES** |
| `N4` | Merged into `51` (`H10+N4`) | `51`: [`./frama-c-kernel-float-const-printing.md`](./frama-c-kernel-float-const-printing.md) | **YES** |
| `N5` | Confirmed TP — package + patch | `79`: [`./frama-c-kernel-int128-const-printing.md`](./frama-c-kernel-int128-const-printing.md) | NO |
| `N6` | Confirmed TP — package + patch (includes `utmp.h` sibling) | `74`: [`./frama-c-libc-reentrant-result-pointer-assigns.md`](./frama-c-libc-reentrant-result-pointer-assigns.md) | **YES** |
| `N7` | Confirmed TP — package + patch | `80`: [`./frama-c-kernel-hex-float-double-rounding.md`](./frama-c-kernel-hex-float-double-rounding.md) | **YES** |
| `N8` | Confirmed TP — package + patch | `57`: [`./frama-c-kernel-bool-cast-dropped-logic.md`](./frama-c-kernel-bool-cast-dropped-logic.md) | **YES** |
| `N9` | Confirmed TP — package + patch | `81`: [`./frama-c-kernel-acsl-adjacent-string-concat.md`](./frama-c-kernel-acsl-adjacent-string-concat.md) | NO |
| `N10` | Confirmed TP — package + patch | `82`: [`./frama-c-kernel-acsl-unknown-escape-char.md`](./frama-c-kernel-acsl-unknown-escape-char.md) | NO |
| `N11` | Confirmed TP — package + patch | `60`: [`./frama-c-kernel-acsl-wstring-octal-escapes.md`](./frama-c-kernel-acsl-wstring-octal-escapes.md) | NO |
| `N12` | Confirmed TP — package + patch | `78`: [`./frama-c-kernel-acsl-wstring-double-escape.md`](./frama-c-kernel-acsl-wstring-double-escape.md) | NO |
| `N13` | Confirmed TP — package + patch | `83`: [`./frama-c-kernel-clexer-universal-char-names.md`](./frama-c-kernel-clexer-universal-char-names.md) | NO |
| `N14` | Merged into `77` (`H12+N14`) | `77`: [`./frama-c-kernel-wstring-escape-trigraph.md`](./frama-c-kernel-wstring-escape-trigraph.md) | NO |
| `N15` | Confirmed TP — package + patch | `84`: [`./frama-c-kernel-logic-constfold-div-zero.md`](./frama-c-kernel-logic-constfold-div-zero.md) | NO |
| `N16` | Confirmed TP — package + patch | `71`: [`./frama-c-wp-par-range-check.md`](./frama-c-wp-par-range-check.md) | NO |
| `N17` | Confirmed TP — package + patch | `85`: [`./frama-c-kernel-machdep-zero-size-crash.md`](./frama-c-kernel-machdep-zero-size-crash.md) | NO |
| `N18` | Confirmed TP — package + patch | `86`: [`./frama-c-kernel-narrow-char-escape-range.md`](./frama-c-kernel-narrow-char-escape-range.md) | NO |
| `N19` | Confirmed TP — package + patch | `87`: [`./frama-c-kernel-logic-preprocess-unbalanced-quote.md`](./frama-c-kernel-logic-preprocess-unbalanced-quote.md) | NO |
| `N20` | Confirmed TP — package + patch | `76`: [`./frama-c-libc-wchar-stdio-streams.md`](./frama-c-libc-wchar-stdio-streams.md) | NO |
| `N21` | Skipped (read-only notes) | — | NO |

## How to read this file

- **Who found what:** four subagents, one per family (`models`, `syntax`, `regex`, `libc`), and
  the parent session while it prepared 43 (`parent`). They gave H1 to H19 and L1 to L6.
- **Second opinion:** at the owner's request, six reviewer subagents on another model (`v1-wp`,
  `v2-kernel`, `v3-print`, `v4-acsl`, `v5-text`, `v6-libc`) then tried to refute every candidate
  on the image `framac-master-audit:b80fcac` (plain `master` `b80fcac74f`) and on `34.0~beta`,
  searched the tracker with several wordings, and looked for the same mistake elsewhere. Their
  verdicts are in [Verdicts of the second opinion](#verdicts-of-the-second-opinion); each entry
  below carries its corrections; what they found beside the candidates is N1 to N21, in
  [New candidates from the second opinion](#new-candidates-from-the-second-opinion).
- **Who ran what:** an entry says "parent re-ran" when the parent session ran the reproducer
  itself on plain `master` `b80fcac74f` after the reviewer. "Reviewer's run" means only the
  reviewer ran it. "Read" means nobody ran it.
- **Re-run of H1 to H19:** the subagents ran on the image `framac-master-audit:9540804` (`master`
  `95408044f7`) and on `34.0~beta`. The parent session then ran every reproducer below again on
  `master` `b80fcac74f` (the same container as 43's validation: the audit image's tree moved to
  that commit, rebuilt and installed). Every one gave the output written here. A finding that was
  not run again says so.
  - That container had 43's patch installed on top of `b80fcac74f`. The patch changes
    `plugins/e-acsl/src/code_generator/gmp.ml` (and its `.mli`) only, so the kernel, WP and Eva
    are `master`'s. The E-ACSL runs (the generated code of H6, and H10, H11 and H15) are
    therefore on `master` plus that patch; H10, H11 and H15 gave the same output on `34.0~beta`
    without it. The reviewers and the parent's later runs used plain `master` (the image
    `framac-master-audit:b80fcac`), with the same results.
- **Source lines:** the lines of `Cmath.ml`, `Cfloat.ml`, `Vset.ml`, `logic_utils.ml`, `cil.ml`
  (2489), `floating_point.ml` and `e-acsl-gcc` were read on `b80fcac74f`. The other line numbers
  in the first reports come from the subagents, who read a checkout of `3dff90fc70`; they may be
  off by a few lines. The lines quoted under "Second opinion" and in L1 to N21 were read by the
  reviewers on `b80fcac74f`.
- **34.0~beta:** every finding of the subagents shows there too (their runs). The parent's three
  (H10, H11, H15) and the `-float-print hex` workaround were run there by the parent, with the
  same output as on `master`.
- **Duplicates:** each subagent compared with packages 01 to 42 and searched the tracker
  (read-only) with the keywords of its entry. The reviewers searched again, issues and merge
  requests in all states, and found no duplicate for any entry (their search words are in their
  reports). The one open question is L4 against #2806: distinct by reading, not confirmed by a
  build of !37.
- **Commands:** `WPQ` stands for `-wp -wp-prover none -wp-print`. With it, `Prove: true.` means
  that WP's own simplifier (Qed) proved the goal, without any prover.

## Verdicts of the second opinion

Every candidate reproduces on `master` `b80fcac74f` and on `34.0~beta`. Two are not bugs to
report (H9, H19). No duplicate was found on the tracker.

| # | Component | Short name | Verdict | Main correction |
| :-- | :-- | :-- | :-- | :-- |
| H1 | WP | `\floor`, `\ceil`, `\truncate` and C casts of a constant | confirmed, with corrections | wider than reported; above 2^63 the result depends on the hardware |
| H2 | WP | A constant rounded to `float` is rounded twice | confirmed | ISO C alone allows either neighbour for the C form; IEEE and ACSL do not |
| H3 | WP | The sum of two ranges ignores an empty range | confirmed | the same rule is in pointer shifts (N2), which matters more |
| H4 | Kernel | `(float)` of a `double` literal is dropped in the logic | confirmed, with corrections | Eva also calls true properties invalid and stops |
| H5 | Kernel | Character constants are sign-extended | confirmed, with corrections | only `ppc_32` among the bundled machdeps; no ARM one |
| H6 | Kernel (ACSL lexer) | A hexadecimal escape is cut into pairs of digits | confirmed, with corrections | the ordinary trigger is a wide constant such as `L'\x20AC'` |
| H7 | Kernel (ACSL typing) | A string literal is sized from its escaped text | confirmed, with additions | the ordinary trigger is a macro ending in `\n` |
| H8 | Kernel | A multi-character constant is not an `int` | confirmed, with corrections | four characters give `unsigned long long` |
| H9 | Kernel | UTF-8 bytes in a wide literal are not decoded | **not a wrong result** | implementation-defined; at most a request for a warning |
| H10 | Kernel (printer) | A constant without source text is printed with 12 digits | confirmed, with corrections | only `double` values change; the printer is the place to fix |
| H11 | E-ACSL | A rational cast to `double` is truncated | confirmed, worse | false assertions also pass |
| H12 | Kernel (printer) | Wide escapes are printed in the 4-digit universal form | confirmed, with corrections | four distinct failures; the C lexer reads no universal name (N13) |
| H13 | Kernel | Compilation database: flags are not quoted for the shell | confirmed, with corrections | the `"command"` form too; command execution read, not demonstrated |
| H14 | Eva (`numerors`) | Literals read by a decimal-only parser | confirmed, worse | a sure alarm is lost with `DBL_MAX` |
| H15 | E-ACSL, printer | An infinite constant is printed as `inf` | confirmed | plain C reaches the same printer (N4) |
| H16 | WP | A `strategy` timeout with a suffix | confirmed | also `99999999999999999999`, without a suffix |
| H17 | WP | `-wp-time-margin` is not checked | confirmed | the manual says "Default is 5s"; the code's default is 0.5 |
| H18 | Kernel (ACSL lexer) | An octal escape above `\377` | confirmed, with corrections | `L'\777'` is valid C and crashes too |
| H19 | WP | `INFINITY` under `-wp-model +real` | **not a bug** | documented limit of the model; nothing false is proved |
| L1 | WP | A `void` object is sized as an `int` | confirmed, with corrections | also the default `Typed` model, through `\block_length(void *)` |
| L2 | libc | `pclose`: `\false` is provable after a call | confirmed | a libc bug; WP's "reads nothing" is a second weakness |
| L3 | libc | `sigaction`: what `oldact` receives | confirmed, with corrections | one call is enough; two clauses are wrong |
| L4 | E-ACSL | `typing was not performed` on `stpncpy`, `strlcat` | confirmed, with corrections | two crash paths; not #2806 by reading |
| L5 | libc | `syslog` with only `<syslog.h>` | confirmed | a lesser sibling in `<wchar.h>` (N20) |
| L6 | E-ACSL | Internal `Failure` lines on `getaddrinfo` | confirmed | cosmetic; no report of its own |

## Order of criticity

This ranking covers 43, H1 to H19, L1 to L6 and N1 to N21. "Ordinary input" means code or
annotations that a user writes without trying to break the tool.

| Rank | # | What goes wrong | Reach |
| :-- | :-- | :-- | :-- |
| 1 | N1 | An enumeration constant is unsigned: WP proves a negative index safe, Eva gives wrong statuses, the E-ACSL binary takes another branch | ordinary C, default machdep, all three analyses |
| 2 | L2 | After any `pclose`, WP proves `\false` | ordinary C with Frama-C's libc |
| 3 | L1 | WP sizes a `void` object as an `int`: `\block_length(void *)` is 4 times too large (default model), `void *` shifts step by 4 bytes (`Bytes`) | ordinary contracts on `void *` buffers |
| 4 | L3, N6 | After `sigaction` with `oldact`, Eva stops; after `getpwnam_r`, the success branch is dead | ordinary C with Frama-C's libc |
| 5 | H10, N4 | The printed program computes other `double` values, or does not compile (`inf`); default `e-acsl-gcc` | ordinary C |
| 6 | H11 | E-ACSL rejects true assertions and accepts false ones with `(double)` of a real | ordinary annotations |
| 7 | H7 | `sizeof` of a string literal with an escape is wrong in annotations: Eva stops, WP refutes a correct contract | ordinary (a message macro) |
| 8 | H6 | A wide character constant in an annotation has a nonsense value: a correct program aborts under E-ACSL | ordinary for wide characters |
| 9 | H1 | WP proves false facts about `\floor` and about `(long long)` of a large `double` | plain C, uncommon values |
| 10 | L5 | `syslog` without `<stdio.h>` loses its string preconditions: Eva reports no alarm | ordinary C with Frama-C's libc |
| 11 | N2 | `p + (a..b) + (c..d)` ignores an empty range: an `assigns` and a validity are proved | unusual, ordinary-looking |
| 12 | H4 | An explicit `(float)` on a literal is dropped: wrong proof, lost alarms | mildly contrived |
| 13 | 43 | E-ACSL: `1e-9` stops the build, `0.1L` is silently 0 | ordinary annotations |
| 14 | H5 | Character constants above 127 are negative on unsigned-`char` machdeps | `ppc_32`, custom machdeps |
| 15 | H14 | `numerors`: a sure alarm is lost | experimental opt-in domain |
| 16 | N3 | WP computes with an infinite "real" constant; the prover export fails on it | after an overflow that RTE flags |
| 17 | H2, H3, H8, N5, N7 to N12 | Wrong value or proof | contrived input |
| 18 | H13, H12, N14 | Another program is analysed or printed | uncommon input |
| 19 | L4, H15, N13, H18, N19, H16, H17, N15 to N18, N20, N21, L6 | Internal error, generated C that does not compile, or a lost side effect | loud or minor |
| none | H9, H19 | Not bugs to report | |

## WP and the logic: wrong proofs

### H1. `\floor`, `\ceil`, `\truncate` and float-to-integer casts of a constant (`models`)

```c
/*@ check lemma floor_wrong: \floor(0.99999999999999999999) == 1;
    check lemma floor_huge:  \floor(1e30) == 0; */

/*@ ensures \result == -4223372036854775808; */
long long trunc_big(void) { double d = 5e18; return (long long)d; }
```

- **Command:** `frama-c WPQ r1.c`
- **Output:** `Prove: true.` for `floor_wrong`, `floor_huge` and the post-condition of
  `trunc_big`. With the default prover: `Proved goals: 5 / 5`.
- **Truth:** all three are false. The floor of 1 - 10^-20 is 0. The floor of 10^30 is 10^30.
  5e18 is exactly a `double` and fits in `long long` (below 2^63), so the cast gives
  5000000000000000000; the value Qed uses is 5e18 - 2^63.
- **Cause:** `plugins/wp/src/Cmath.ml`, `builtin_truncate` (lines 42-61), computes
  `int_of_float (Q.to_float r)`.
  - Rounding the rational to a `double` loses a fractional part close to an integer.
  - `int_of_float` wraps above OCaml's 63-bit `int` without raising, so the `with _` handler does
    not help. The comment there says "Waiting for Z-Arith to have truncation to big-int"; Zarith
    has `Q.to_bigint` and `Z.fdiv`/`Z.cdiv`.
  - C casts reach it through `Cint.of_real`.
- **Models:** default, `real`, `nat`, `nat+real` (the subagent's runs).
- **Tracker:** `wp floor`, `truncate`, `int_of_float`: #959 (closed, a `\floor` crash) and #2792
  (closed, shift rules) only.
- **Second opinion (`v1-wp`): confirmed, with corrections.**
  - "`int_of_float` wraps" holds only for magnitudes in [2^62, 2^63). At or above 2^63 OCaml
    leaves the result unspecified; on this x86-64 image it is 0, also for infinity and NaN. So
    `\floor(1e30) == 0` depends on the hardware.
  - The defect is wider. All of these are false and get `Prove: true.` (reviewer's run, both
    versions; the parent re-ran the last two on `master`):
    `\ceil(0.99999999999999999999) == 2`, `\truncate(-0.99999999999999999999) == -1`,
    `\floor(9007199254740993.0) == 9007199254740992`, `(integer)0.99999999999999999999 == 1`,
    `\floor(9007199254740993.5) == 9007199254740994` (the floor exceeds its argument) and, in C,
    `float f = 4611686018427387904.0f; return (unsigned long long)f;` with
    `ensures \result == 13835058055282163712`.
  - The WP manual states the intent: "Constants (rationals) are truncated towards the expected
    direction." No limitation is documented.
  - **Fix direction:** `Q.to_bigint` for truncation, `Z.fdiv` and `Z.cdiv` on the numerator and
    denominator for floor and ceil.

### H2. A real or integer constant rounded to `float` is rounded twice (`models`)

```c
/* x = 2^60 + 2^36 + 1; the nearest float is 2^60 + 2^37 = 1152921642045800448 */
/*@ ensures \result == 1152921504606846976.0; */
float to_float(void) { long long x = 1152921573326323713LL; return (float)x; }
```

- **Command:** `frama-c WPQ r2.c`
- **Output:** `Prove: true.` for the post-condition. With the default prover: `3 / 3`.
- **Truth:** false. At 2^60 two neighbouring `float` values are 2^37 apart, and x - 2^60 is more
  than half of that, so the cast gives 2^60 + 2^37.
- **Cause:** `plugins/wp/src/Cfloat.ml` line 131, `qmake ulp q = fmake ulp (Q.to_float q)`: the
  exact value goes to a `double` first (2^60 + 2^36, a tie), then to single precision (ties to
  even: 2^60). The subagent read the path `float_of_int` -> `float_of_real` -> `round` -> `qmake`.
- **Same cause, in ACSL** (the subagent's run):
  `check lemma dr1: (float)1.0000000596046447753906250000000000000001 == 1.0;` is proved.
- **Models:** the default Float model. Under `+real`, `(float)` is the identity by design.
- **Not 42:** the literals are decimal or integers, and are read exactly. The fault is the
  rounding that follows.
- **Second opinion (`v1-wp`): confirmed** (reviewer's run, both versions).
  - **The case against, which holds in part:** C17 6.3.1.4p2 lets an implementation pick either
    neighbour for an inexact integer-to-float conversion, so 2^60 is allowed by ISO C alone. It is
    wrong under IEC 60559 (which gcc follows, and which the WP manual claims for its Float
    model), and the ACSL lemma form has no such latitude.
  - **Same cause at the overflow threshold:** `(float)340282356779733661637539395458142568447.0`
    is `FLT_MAX` in ACSL, and WP refutes that true lemma.
  - **Clean:** `float` `+`, `*`, `/` on constants, `(float)` of a `double` constant, suffixed
    literals, `double` operations.
  - **Reach:** a constant must fall within about 2^-29 (relative) of a `float` midpoint. A real
    user is unlikely to meet it.

### H3. The sum or difference of two ranges ignores an empty range (`models`)

```c
/*@ check lemma empty_plus: 8 \in ((5..3) + (0..10));
    check lemma empty_minus: -2 \in ((5..3) - (0..10)); */

/*@ requires n == 0;
    ensures 5 \in ((0 .. n-1) + (0 .. 10)); */
void g(int n) { }
```

- **Command:** `frama-c WPQ r4.c`
- **Output:** `Prove: true.` for both lemmas and the post-condition. Default prover: `5 / 5`.
- **Truth:** `(5..3)` is empty (WP's own `Vset.is_empty` says so), and so is `(0..n-1)` with
  `n == 0`. An operation lifted over an empty set gives the empty set.
- **Cause:** `plugins/wp/src/Vset.ml`, `lift_add` (lines 362-363) and `lift_sub` (376-377):
  `Range(a,b), Range(c,d) -> Range(a+c, b+d)` without the condition that both ranges are
  non-empty.
- **Second opinion (`v1-wp`): confirmed** (reviewer's run, both versions).
  - `tset + tset` is in the ACSL grammar and defined as the set of sums; a range `t1..t2` with
    `t1 > t2` "is the same as `\empty`". `tset - tset` is not in the grammar; the kernel accepts
    it.
  - Open ranges behave the same (`(..3) + (5..4)`), and so does a range that is empty only under
    a hypothesis.
  - True statements are refuted too: `\subset((5..3) + (0..10), \empty)` gives `Prove: false.`
  - The same rule exists in the pointer-shift code, where it needs no set arithmetic: see N2.

### H4. Kernel: `(float)` of a literal that is exact as a `double` is dropped (`models`)

```c
/*@ check lemma cast_dropped: (float)16777217.0 == 16777217.0; */

int main(void) {
  //@ check (float)16777217.0 == 16777217.0;
  return 0;
}
```

- **Commands:** `frama-c r3.c -print`, `frama-c WPQ r3.c`, `frama-c r3.c -eva`
- **Output:**
  - `-print`: `check lemma cast_dropped: 16777217.0 ≡ 16777217.0;` (the cast is gone);
  - WP: `Prove: true.` for both;
  - Eva: `Assertions 1 valid 0 unknown 0 invalid 1 total`.
- **Truth:** 16777217 is 2^24 + 1, which is not a `float`: the cast gives 16777216.0, and the
  property is false.
- **Cause:** `src/kernel/services/ast_queries/logic_utils.ml` lines 332-333 replace `(float)lit`
  by `lit` when `Cil.isExactFloat fk r` holds, and that function
  (`src/kernel/services/ast_queries/cil.ml` lines 2489-2490) tests `r.r_upper = r.r_lower`, which
  means exact as a `double`, and that the value stays finite once rounded to single precision.
  It never tests that the value is exact as a `float`.
- **Also uses it (read, not run):** `plugins/aorai/src/aorai_utils.ml` line 393.
- **Second opinion (`v2-kernel`): confirmed, and understated.** Eva gives true properties the
  status "invalid", and an `assert` on one stops the analysis (parent re-ran, both versions):

  ```c
  int g;
  void dead(int z) {
    //@ assert (float)16777217.0 == 16777216.0;
    g = 10 / z;
  }
  int main(void) {
    float lim = 2147483647.0f;       /* 2^31 */
    float big = 1e11f;               /* 99999997952 */
    //@ check true_1: lim <= (float)2147483647.0;
    //@ check true_2: big == (float)1e11;
    //@ check true_3: (float)1e11 == 99999997952.0;
    dead(0);
    return 0;
  }
  ```

  - `frama-c h4b.c -eva`: `true_1`, `true_2` and `true_3` get status invalid; then
    `assertion got status invalid (stopping propagation)` and `0 alarms`: the division by zero
    after the true assertion is never reported.
  - **When the cast is dropped wrongly:** an explicit `(float)` on an unsuffixed literal that is
    exact as a `double` and not as a `float`: `1e11` to `1e22`, `2147483647.0`, `4294967295.0`,
    any integer above 2^24 written with a decimal point. `(float)0.1`, `(float)16777217` (an
    integer literal), `16777217.0f` and the casts that RTE generates are right.
  - **History:** commit `e180d54c70` (2020, "[kernel] fix cast on non-exact floats") replaced
    `isFiniteFloat` by `isExactFloat`, so the intent was "drop only when exact".
  - **Fix direction:** also require that rounding the value to `fk` leaves it unchanged.

## Kernel: literals of the C and ACSL front ends

All seven (H5 to H9, H12, H18) were found by `syntax`. Its related tracker items: #154 (closed, the ACSL lexer crashed
on `'\v'`) and #2672 (open, `sizeof(L"AA")` evaluated as a pointer size); both are distinct.

### H5. Character constants are sign-extended whatever the machdep

```c
int main(void) {
  int h = '\377';
  char c = 255;
  //@ check h1: h == 255;
  //@ check h2: h == c;
  //@ check h3: '\377' == 255;
  return 0;
}
```

- **Command:** `frama-c p6_uchar.c -machdep ppc_32 -eva`
- **Output:** `check 'h1' got status invalid`, and the same for `h2` and `h3`. `-print` shows
  `int h = '\377';`.
- **Truth:** on `ppc_32`, `char` is unsigned (`-print-machdep`), so `'\377'` is 255 (C11
  6.4.4.4p10; `gcc -funsigned-char` agrees). Frama-C also disagrees with itself: `c` is 255 and
  `h` is -1.
- **Cause (read by the subagent):** `cil.ml` `charConstToInt` (2542-2546) always sign-extends.
  WP (`Ctypes.ml:232`), Eva (`eval_terms.ml:1034`) and E-ACSL (`interval.ml:352`) use it.
- **Who it concerns:** every machdep where `char` is unsigned. Among the 11 bundled machdeps
  that is `ppc_32` only (no bundled ARM machdep has an unsigned `char`); a custom machdep for
  ARM or PowerPC Linux would be concerned too (not run). The default machdep and the pipeline's
  `gcc_x86_64` are not.
- **Second opinion (`v2-kernel`): confirmed, with the correction above** (reviewer's run, both
  versions).
  - The realistic symptom, under `-machdep ppc_32 -eva`: `a[0] == '\377'` on
    `char a[] = "\377"` evaluates to 0 (gcc `-funsigned-char`: 1), `'\200' < 0` to 1,
    `'\xff' == 255` to 0, and a `switch (c) { case '\377': ...}` takes `default`. A comparison
    that is wrongly false makes code dead, so alarms are lost.
  - The kernel folds `sizeof(char[('\377' > 0) ? 2 : 1])` to `sizeof(char [1])`.
  - `ast_info.ml` 22-23 and 70-71 carry the comment "This is against the ISO C norm! See
    Cil.charConstToInt".
  - **Fix direction:** `charConstToInt` consults the machdep's `char` signedness.

### H6. ACSL: a hexadecimal escape is cut into pairs of digits

```c
int main(void) {
  char c = '\x041';
  //@ check ok: c == 'A';
  //@ check bad1: '\x041' == 'A';
  //@ check bad2: '\x041' == 1025;
  //@ check bad3: L'\x20AC' == 0x20AC;
  return 0;
}
```

- **Commands:** `frama-c WPQ r1_hexesc.c`, `-eva`, `-e-acsl -then-last -print`
- **Output:** WP: `bad1` `Prove: false.`, `bad2` `Prove: true.`, `bad3` `Prove: false.`. Eva:
  `bad1` and `bad3` invalid. E-ACSL generates `__e_acsl_assert(0, ...)` for `bad1`, so a correct
  program would abort.
- **Truth:** in C, `'\x041'` is one escape of value 0x41 (the C front end agrees: `ok` holds).
  The ACSL lexer reads it as `'\x04'` followed by `'\x01'`, the multi-character value 1025.
- **Cause (read by the subagent):** `src/kernel/internals/parsing/logic_lexer.mll`, rule `chr`
  (524-541), against `clexer.mll` `scan_hex_escape` (288-297).
- **Same area:** in an ACSL wide string, `8` and `9` count as octal digits
  (`logic_typing.ml:26-35`); see N11.
- **Second opinion (`v4-acsl`): confirmed, with corrections.**
  - The ordinary trigger is a wide constant: four hexadecimal digits are the normal spelling of
    a code point above 0xFF. Parent re-ran on `master`:

    ```c
    #include <stddef.h>
    #include <stdio.h>
    int main(void) {
      wchar_t w = L'\x20AC';
      printf("w=%#x\n", (unsigned)w);
      /*@ assert euro: w == L'\x20AC'; */
      printf("done\n");
      return 0;
    }
    ```

    `e-acsl-gcc -c -o he6.gen.c -O he6 he6.c && ./he6.e-acsl` aborts (exit 134) with
    `Assertion failed: euro: w ≡ 137438953644. With values at failure point: - w: 8364`. The
    plain gcc build prints `w=0x20ac`, `done`.
  - The value is 0x20000000AC: a second cause, `logic_typing.ml:1155-1173` (`parseInt`), folds
    the bytes with 32-bit shifts and does not truncate to `wchar_t`, as `cabs2cil.ml` does on
    the C side. For the same reason `L'ab'` is 0x6100000062 in ACSL and 98 in C.
  - Narrow ACSL strings are cut the same way (`logic_typing.ml:19`, `unescape`):
    `strlen("\x041") == 1` is invalid for Eva.
  - ACSL wide strings are read by a third implementation that gets it right
    (`L"\x20AC"[0]` is 8364), and an upstream oracle records that
    (`tests/spec/oracle/string.0.res.oracle`). So ACSL disagrees with itself.
  - **Ground truth:** the ACSL manual says literals "are the same as the corresponding C lexical
    tokens" and "adopted from C without modification".
  - **Fix direction:** the rule `chr` returns a list of code values as `clexer.mll` does, and the
    wide value is truncated as in `cabs2cil.ml`.

### H7. ACSL: a string literal is sized from its escaped text

```c
int main(void) {
  //@ check bad1: sizeof("\n") == 2;
  //@ check bad2: sizeof("\n") == 3;
  return 0;
}
```

- **Commands:** `frama-c WPQ r3_strsize.c`, `-eva`
- **Output:** WP: `bad1` `Prove: false.`, `bad2` `Prove: true.`. Eva: `bad1` invalid.
- **Truth:** `sizeof("\n")` is 2.
- **Cause (read by the subagent):** `logic_typing.ml:2684` types the literal from the text that
  still has its backslash.
- **Second opinion (`v4-acsl`): confirmed, with additions.**
  - Every escape is concerned (`"a\0b"`: 5 for 4, `"\x41"`: 5 for 2, `"\\"`: 3 for 2). The
    contents of the literal are right (`strlen("a\nb") == 3` is valid); only its type is wrong.
  - The ordinary trigger is a macro, since macros are expanded in annotations. Parent re-ran on
    `master`:

    ```c
    #include <string.h>
    #define GREETING "hello\n"
    char out[sizeof(GREETING)];
    /*@ assigns \nothing;
        ensures len: \result == sizeof(GREETING); */
    unsigned long greeting_size(void) { return sizeof(GREETING); }
    /*@ requires room: \valid(buf + (0 .. sizeof(GREETING) - 1));
        assigns buf[0 .. sizeof(GREETING) - 1]; */
    void greet(char *buf) { memcpy(buf, GREETING, sizeof(GREETING)); }
    int main(void) {
      //@ check c1: sizeof(GREETING) == sizeof(out);
      greet(out);
      return 0;
    }
    ```

    - `frama-c WPQ h7b.c`: `Post-condition 'len' in 'greeting_size': Prove: false.` and
      `Check 'c1': Prove: false.` Both are true.
    - `frama-c h7b.c -eva`: `check 'c1' got status invalid`,
      `function greet: precondition 'room' got status invalid`, `NON TERMINATING FUNCTION`: the
      analysis of a correct program stops at the call.
  - E-ACSL is not concerned: it stops cleanly on any annotation with a string literal
    ("unimplemented feature").
  - The array typing came with commit `db4b010a04` (2025-07-24, "[logic] type string literal as
    arrays"), so the symptom exists at least since `32.0-beta`.
  - **Fix direction:** type `unescape s`, not `s`.

### H8. A multi-character constant has type `unsigned long`

```c
int main(void) {
  int lt = ('ab' - 30000) < 0;
  int sz = sizeof('ab');
  //@ check t1: lt == 1;
  //@ check t2: sz == sizeof(int);
  return 0;
}
```

- **Commands:** `frama-c r4_multichar.c -print`, `-eva`
- **Output:** `int lt = 24930UL - (unsigned long)30000 < (unsigned long)0;` and
  `int sz = (int)sizeof(24930UL);`. Eva: `t1` and `t2` invalid.
- **Truth:** an integer character constant has type `int` (C11 6.4.4.4p10); gcc gives 1 and 4.
- **Cause (read by the subagent):** `cil.ml:4145-4156`, `interpret_character_constant`.
- **Second opinion (`v2-kernel`): confirmed, with a correction** (parent re-ran on `master`).
  - A value of 256 or more becomes `unsigned long`, and above `INT32_MAX` it becomes
    `unsigned long long`: `int cmp = ('\377\377\377\377' < 0);` is printed
    `4294967295ULL < (unsigned long long)0`, and `long long hi4 = '\377\377\377\377';` is
    4294967295 where gcc gives -1. `_Generic('ab', int: 1, unsigned long: 2, ...)` is 2.
  - Only the value of a multi-character constant is implementation-defined; its type is `int`.
  - In ACSL, `'ab'` is the integer 24930 with no C type, so only the C side is concerned.
  - **Reach:** rare input (four-character tags); it shows only when signedness or size matters.
  - **Fix direction:** build an `int` constant, with the value wrapped as gcc does.

### H9. UTF-8 bytes in a wide literal are not decoded

```c
#include <stddef.h>
int main(void) {
  wchar_t e = L'€';
  //@ check w1: e == 0x20AC;
  //@ check w2: sizeof(L"€") == 2*sizeof(wchar_t);
  return 0;
}
```

- **Commands:** `frama-c r6_utf8wide.c -print`, `-eva`
- **Output:** `wchar_t e = 172;`, no warning. Eva: `w1` and `w2` invalid.
- **Truth:** gcc gives 0x20ac and 8.
- **Cause (read by the subagent):** `clexer.mll` makes one wide character per source byte, and
  `cabs2cil.ml:5749` folds the three bytes with `reduce_multichar`.
- **Second opinion (`v4-acsl`): the behaviour is as reported, the "truth" is not. Do not file it
  as a wrong result.**
  - How source bytes map to characters is implementation-defined (C11 5.1.1.2p1, 6.4.4.4p11,
    6.4.5p6). Frama-C's reading is coherent: it equals `gcc -finput-charset=latin1`
    (`e=0xac s0=0xe2 sizeof(s)=16`), without gcc's warning.
  - Frama-C's preprocessing command passes `-U__STDC_ISO_10646__`, so it does not promise that
    `wchar_t` holds code points, and the comment at `cabs2cil.ml:5742-5748` shows the choice is
    deliberate.
  - What remains: the choice is silent, differs from the default of the compilers that the
    machdeps model, and is documented nowhere (`doc/userman`, the man page, the Changelog). At
    most a request for a warning or for a sentence in the manual.
  - Narrow strings are right (`sizeof("€") == 4`).

### H12. The printer writes wide escapes as `\u`

```c
#include <stddef.h>
#include <stdio.h>
wchar_t a[] = L"\x20AC";
wchar_t b[] = L"\x1F600";
int main(void) {
  printf("a0=%x b0=%x sizeof(b)=%zu\n", (unsigned)a[0], (unsigned)b[0], sizeof(b));
  return 0;
}
```

- **Commands:** `frama-c p5b.c -print -ocode out.c`, `frama-c out.c`, then gcc on both files.
- **Output:** `out.c` holds both literals as a universal character name with a lower-case `u`
  followed by the hexadecimal digits as they come: `20ac` (four digits) and `1f600` (five). (The
  sequence itself is not written in this file: the tool that writes it turns a backslash, `u`
  and four digits into the character.) Frama-C rejects its own output
  (`Unrecognized escape sequence`). The original prints `b0=1f600`; `out.c` compiles without a
  warning and prints `b0=1f60`.
- **Truth:** U+1F600 is written `\U0001f600`: the lower-case form takes exactly four digits, the
  upper-case form exactly eight (C11 6.4.3).
- **Cause (read by the subagent):** `src/lib/utils/escape.ml:64-69`. E-ACSL's generated code goes
  through the same printer.
- **Second opinion (`v3-print`): confirmed, with corrections** (reviewer's run, both versions).
  - There are four distinct failures, not two:

    | Literal | Printed with | Result |
    | :-- | :-- | :-- |
    | `L"\x20AC"` | 4 digits | gcc reads the same value; Frama-C cannot read it back |
    | `L"\x1F600"`, `L"\x110000"`, `L"\x7FFFFFFF"`, `L"\xFFFFFFFF"` | 5 to 8 digits after the lower-case `u` | gcc reads the first four digits as the character and the rest as text, without a warning |
    | `L"\xD800"` | 4 digits | gcc: "is not a valid universal character" |
    | `L"\x100000000"` (gcc warns only) | nothing | `Unexpected error (Invalid_argument("Cprint.escape_string_intlist"))` on `master` |

  - Through `e-acsl-gcc -c` the instrumented program prints `b0=1f60`.
  - An upstream oracle records the 4-digit form (`tests/spec/oracle/string.0.res.oracle:9`);
    none covers a value above 0xFFFF.
  - **Cause, confirmed:** `escape.ml` 66-67 print 4 digits below 0x10000; 68-69 print the same
    format up to 2^32, where the 8-digit upper-case form was meant; 71 raises.
  - **Fix direction:** print such a character as a `\x` escape and close and reopen the literal
    when a hexadecimal digit follows, as the ACSL printer does (`cil_printer.ml:2398-2412`). The
    8-digit form alone would still be wrong for surrogates and above 0x10FFFF, and Frama-C could
    not read it back (N13).
  - **Clean:** narrow strings with bytes above 127, an embedded NUL, octal escapes followed by
    digits, all character constants, wide character constants (printed as integers).

### H18. ACSL: an octal escape above `\377`

- **Reproducer:** `//@ check o1: '\777' == 0;` in a `main`. **Command:** `frama-c p4_oct.c`
- **Output:** `Failure: Unknown error (Invalid_argument("Char.chr"))`, an internal error.
- **Second opinion (`v4-acsl`): confirmed, with corrections.**
  - "The input is invalid" is wrong for the wide form. `wchar_t w = L'\777';` is valid C (gcc:
    511; Frama-C's C side accepts it), and `//@ check o2: w == L'\777';` stops Frama-C the same
    way, exit 4 (parent re-ran on `master`).
  - A narrow string takes another path: `//@ check o3: \valid_read("\777");` gives
    `Unexpected error (Invalid_argument("Char.chr"))`, exit 125, from `logic_typing.ml:2684`.
  - **Cause:** `logic_lexer.mll:542-551`, `Char.chr c` with `c` up to 511. The same root as H6:
    the rule stores code values as bytes.
  - The digit-separator crash is a general defect of the annotation preprocessor: see N19.

## Printing floating-point constants

### H10. A constant without source text is printed with 12 significant digits (`parent`)

`Floating_point.pretty` (`src/lib/floating_point/floating_point.ml`, `Default` mode) prints with
`"%.*g" 12`. A constant that kept its source text is printed from that text; one built by
Frama-C is not, and loses up to five digits. Two places where the printed C is compiled. The
program below is an excerpt of the one that was run (which printed three more values, all
unchanged), with the matching part of its output:

```c
#include <stdio.h>
static const double third = 1.0 / 3.0;
double scale(unsigned char c) { return c * (1.0 / 255.0); }
int main(void) {
  double t = 1.0 / 3.0;
  double h = 2 * 3.141592653589793;
  printf("%a %a %a %a\n", third, scale(255), t, h);
  return 0;
}
```

- **`e-acsl-gcc -c fold.c -O fold && ./fold.e-acsl`** (`e-acsl-gcc` passes `-constfold` unless
  `--no-constfold` is given, line 1005 of the script):
  - the generated C holds `static double const third = 0.333333333333;`,
    `double t = 0.333333333333;` and `double h = 6.28318530718;`;
  - the original prints `0x1.5555555555555p-2 0x1p+0 0x1.5555555555555p-2 0x1.921fb54442d18p+2`;
  - the instrumented program prints
    `0x1.5555555553de1p-2 0x1.ffffffffff735p-1 0x1.5555555553de1p-2 0x1.921fb54442eeap+2`.
  - So the program that E-ACSL monitors is not the program that was written: `scale(255)` is no
    longer 1.
- **Annotations, with or without constant folding:** when a constant of a term is exactly a
  `double` or a `float`, E-ACSL builds it from the kernel's value, so it has no text. (Any other
  constant goes to GMP as a fraction, exactly; see 43.)

  ```c
  int main(void) {
    float f = 0.1f;
    /*@ assert f == 0.1f; */
    return 0;
  }
  ```

  The generated check is `(double)f == 0.10000000149`, and the program aborts
  (`Assertion failed: f ≡ 0.1f`, exit 134). The same for `double d = 0x1p-68;` with
  `assert d == 0x1p-68;` (`d == 3.38813178902e-21`).
- **`frama-c fold.c -constfold -print`** prints the same 12-digit constants.
- **Workaround, run on `master` and on `34.0~beta`:** `-float-print hex`
  (`e-acsl-gcc -F "-float-print hex"`). The generated C then holds `0x1.5555555555555p-2` and
  `0x1.99999a0000000p-4`, both programs above behave as the original, and both assertions hold.
  (`-float-hex` is not an option of either version.)
- **Fix direction, not tried:** `e-acsl-gcc` passes `-float-print hex`, or the printer prints a
  constant without text with enough digits to read back the same value (`%.17g`).
- **Second opinion (`v3-print`): confirmed, with corrections** (reviewer's run, both versions).
  - **Only `double` values change.** A `float` constant printed with 12 digits reads back as the
    same `float` (9 digits are enough). `f == 0.1f` fails because E-ACSL builds the constant as
    a **`double`** (`Cil.kfloat ~loc FDouble lr.r_nearest`, `translate_terms.ml:128-130`), so
    the check compares `(double)f` with a 12-digit `double`.
  - **More annotation constants** (`e-acsl-gcc --keep-going`, true assertions that fail):
    `d1 == 123456789012345.5`, `d4 == 4503599627370497.0`,
    `f15 == 0.100000001490116119384765625`, and an **integer** literal:
    `double d2 = 123456789012345.0; assert d2 == 123456789012345;`
    (`translate_terms.ml:104-105`). All pass with `-float-print hex`.
  - **Which C constants lose their text under `-constfold`** (45 printed values, 16 differ from
    gcc): a negated literal, `0.1 + 0.2`, `(double)0.1f`, `double g = 0.1f;`,
    `(double)1234567890123456789LL`, any folded division, also in a designated initializer or a
    compound literal. A literal alone keeps its text.
  - **Other producers of the same constants:** `-scf` (the Semantic constant folding plug-in,
    reviewer's run): `printf("%a %a %a\n", x, y, (double)w)` becomes
    `printf("%a %a %a\n",0.333333333333,0.666666666667,0.300000011921);`. Read only: Aorai
    (`aorai_utils.ml:392-397`).
  - **`-float-print hex` is not a complete workaround:** it still prints `inf`, `-inf` and
    `NaN` (N4).
  - **A regression for `e-acsl-gcc` users:** the script passes `-constfold` by default since
    commit `d88e9bec7b` (2026-01-14), which is in `33.0-beta`, `33.0` and `34.0-beta`.
  - **The case against does not hold:** `frama-c -kernel-h` says "'default' will print the float
    as is"; the E-ACSL manual tells users to compile the printed code; the kernel knows the digit
    count elsewhere (`logic_utils.ml:263-268` writes `%.16e`); and the maintainers fixed "the
    emitted program computes differently" before (#1304, #2084, both closed).
  - **Where to fix:** the kernel printer (`cil_printer.ml:639-647`): print a `CReal` without
    text in a form that reads back exactly, and a non-finite one as a C expression.
    `Floating_point.pretty` can stay as it is for Eva's display. Making `e-acsl-gcc` pass
    `-float-print hex` would fix one of at least four paths.
  - **Documentation:** `-float-print` is in neither `doc/` nor the Changelog, and
    `doc/userman/user-start.tex:434-437` still documents `-float-hex` and `-float-normal`, which
    `master` rejects. `-float-print norm` prints text that is not C (`1.6000000238418579*2^-4f`).
- **Tracker:** `float-print`, `constfold`, `significant digits`, `round trip`, `reparse` and
  others (the reviewer's search): no duplicate; #1304 and #2084 are related only.

### H11. E-ACSL: a rational cast to `double` is truncated (`parent`)

```c
int main(void) {
  double e = 0.1;
  /*@ assert e == (double)0.1; */
  return 0;
}
```

- **Command:** `e-acsl-gcc -c cast.c -O cast && ./cast.e-acsl`
- **Output:** the generated code computes `__gmpq_get_d(...)` of 1/10 and compares it with `e`;
  the program aborts (`Assertion failed: e ≡ (double)0.1`).
- **Truth:** the assertion holds: `(double)0.1` is the `double` nearest to 0.1, which is `e`.
  `mpq_get_d` rounds toward zero (GMP manual), and 0.1 as a `double` is above 1/10.
- **Second opinion (`v3-print`): confirmed, and worse: false assertions pass.** Parent re-ran on
  both versions:

  ```c
  int main(void) {
    double e = 0x1.9999999999999p-4; /* the double just below 0.1 */
    /*@ assert m1: e == (double)0.1; */
    /*@ assert m2: (double)0.1 < 0.1; */
    return 0;
  }
  ```

  `e-acsl-gcc --keep-going -c h11m.c -O h11m && ./h11m.e-acsl` exits 0 without a message. Both
  assertions are false.
  - **Ground truth:** ACSL: casts `(float)` and `(double)` of a real "are equivalent to applying
    the rounding functions above with the nearest-even rounding mode". A plain GMP program gives
    `mpq_get_d(1/10) = 0x1.9999999999999p-4` under all four rounding modes.
  - About half of the non-representable constants are concerned: those whose nearest `double`
    is further from zero than the real.
  - `(float)` of a rational goes through `double` first: `float f3 = 16777218.0f;` with
    `assert f3 == (float)16777217.0000000001;` fails although it is true. E-ACSL warns there
    ("R to float: double rounding might cause unsoundness"); it gives no warning for `(double)`.
  - A rational compared with a `double` without a cast is right (`__gmpq_cmp`).
  - **Cause, confirmed:** `plugins/e-acsl/src/code_generator/gmp.ml:339-376`, `add_cast`.
  - **Fix direction:** a run-time helper that rounds to nearest (compare the rational with the
    midpoint of `mpq_get_d`'s result and its neighbour), and one of its own for `float`.
- **Tracker:** `mpq_get_d`, `rational cast`, `e-acsl real` and others: no duplicate.

### H15. E-ACSL: an infinite constant is printed as `inf` (`parent`)

- **Reproducer:** `double x = 0.5; /*@ assert x < 1e40f; */` **Command:** `e-acsl-gcc -c`
- **Output:** the generated C holds `__e_acsl_assert(x < inf, ...)`, and the build stops with
  `error: 'inf' undeclared`. The same before and after 43's patch.
- **Note:** `1e40f` overflows a `float`; the kernel accepts it in a term without a warning.
- **Second opinion (`v3-print`): confirmed** (reviewer's run, both versions).
  - `-float-print hex` does not help: it prints `inf` too.
  - **Where `inf` comes from (read):** `logic_utils.ml:294-307` makes a suffixed literal
    `real_of_float literal nearest`, so its three bounds are +infinity;
    `translate_terms.ml:128-130` tests only that the lower and upper bounds are equal, where the
    kernel's `Cil.isExactFloat` also asks for a finite value; the printer then prints `inf`.
  - ACSL lets a too-large suffixed real be +infinity, so the kernel may accept `1e40f`.
    Generating C that does not compile is wrong either way.
  - **Fix direction:** E-ACSL asks for a finite value (otherwise "not yet supported"), and the
    printer writes a non-finite constant as a C expression, which also fixes N4.

### H19. WP: `INFINITY` in the code under `-wp-model +real` (`syntax`)

- **Reproducer:** `#include <math.h>`, `float x = INFINITY; //@ check x > 0;`
  **Command:** `frama-c n_inf.c -wp -wp-model +real -wp-prover none`
- **Output:** `Warning: Unexpected constant literal "INFINITY"`; the subagent saw the value of
  `x` dropped from the goal.
- **Same function as 42** (`Cfloat.parse_literal`). From a reading of 42's patch it does not
  handle the text `INFINITY`; this was not run with the patch.
- **Second opinion (`v5-text`): not a bug.**
  - With `float x = INFINITY;` and the checks `x > 0`, `x < 0` and `\false` (also for `NAN` and
    `HUGE_VAL`), nothing false is proved under `+real`: the checks are "Unknown (Stronger)" and
    `\false` stays unknown.
  - The WP manual says of the Real model: "This is completely unsound with respect to C and IEEE
    semantics." An infinity has no real value, so a warning and a weakened goal is the honest
    outcome. Only the wording of the warning is clumsy.
  - 42's patch does not change it (read: `extract_suffix` returns `None` for `INFINITY` and
    `NAN`, and the same handler catches the `Not_found`).

## Text matched by hand

All four were found by `regex`.

### H13. Compilation database: `-D` values of `"arguments"` are quoted for OCaml

`compile_commands.json`:

```json
[ { "directory": "/tmp/w2", "file": "g.c",
    "arguments": ["gcc", "-DNAME=\"café\"", "-DPRICE=\"$HOME\"", "-c", "g.c"] } ]
```

`g.c`:

```c
const char name[] = NAME;
const char price[] = PRICE;
```

- **Command:** `frama-c -compilation-db compile_commands.json -print g.c`
- **Output:** `char const name[9UL] = "caf\00195\0169";` and
  `char const price[11UL] = "/home/opam";`
- **Truth:** gcc gives `"café"` (6 bytes) and `"$HOME"` (6 bytes); the gcc run is the
  subagent's, not repeated. The analysed program has
  other strings and other sizes, and the second one holds the home directory of whoever runs
  Frama-C.
- **Cause (read by the subagent):**
  `src/kernel/services/ast_queries/json_compilation_database.ml` line 128,
  `quote_define_argument arg = Format.sprintf "%S" arg`, pasted into a command that `sh` runs.
  OCaml writes a non-ASCII byte as a decimal `\ddd`, which C reads as an octal escape, and leaves
  `$` to the shell.
- **Same file, loud:** an `-I` path with a space from `"arguments"` is passed unquoted
  (`-I/tmp/w/my inc`), and the preprocessor fails with `h.h: No such file or directory`.
- **Second opinion (`v5-text`): confirmed, with corrections** (reviewer's run, both versions; it
  did not re-run the `$HOME` half).
  - In a `-D` value only non-printable and non-ASCII bytes break; a space, both quotes and a
    backslash are handled. A real tab in `-DN=1<TAB>+ 2` gives a user error (`int v = 1\t+ 2;`).
  - **The `"command"` form is concerned too:** `"command": "gcc \"-Imy inc\" ..."` gives the same
    `h.h: No such file`, and `"gcc \"-DM=\\\"a b\\\"\" -c c1.c"` gives
    `gcc: error: b": linker input file not found`, where `sh` itself gives `"a b"`.
  - A two-argument `-include` (also `-I`, `-isystem`) is glued to its path without a space or
    quotes: `-includemy inc/h.h`.
  - **New crash:** a lone `"\""` argument gives
    `Unexpected error (Invalid_argument("String.sub / Bytes.sub"))` (lines 144-150,
    `remove_extraneous_quotes`; the handler at 310-312 does not catch it).
  - **Command execution: read, not demonstrated.** The string goes to `Sys.command`
    (`file.ml:663`), so to `sh`; path, `-U` and `-std=` values are pasted bare (lines 139-142),
    and `-D` values sit inside double quotes, where `sh` still expands `$` and backquotes. From
    the code a crafted database can make Frama-C run a command. The reviewer's attempt to test
    it was stopped by a safety filter and was not retried, by the reviewer or by the parent.
  - **The case against:** the `"command"` form is a shell string by specification, so a database
    is trusted input there. The real discrepancy is that `"arguments"` is an argument vector and
    should never be reinterpreted by a shell. The user manual states no restriction.
  - **Fix direction:** `Filename.quote` on every flag.
- **For the pipeline:** not concerned. No script under `scripts/` passes `-compilation-db` or
  `-json-compilation-database` to Frama-C (searched on 2026-11-18); the pipeline builds the
  preprocessor flags itself.

### H14. Eva `numerors`: the literal's text is read with a decimal-only parser

```c
#include "__fc_builtin.h"
void main(void) {
  double x = Frama_C_double_interval(1.0, 2.0);
  double h = x * 0x1.8p1;  /* 0x1.8p1 == 3.0 */
  double d = x * 3.0;
  Frama_C_domain_show_each_hex(h);
  Frama_C_domain_show_each_dec(d);
}
```

- **Command:** `frama-c -eva -eva-domains numerors -eva-msg-key=d-numerors n1.c`
- **Output:** for `h`, `numerors: Real : [0.048 .. 0.096]`; for `d`, `Real : [3. .. 6.]`. The
  cvalue domain gives `[3. .. 6.]` for both.
- **Crashes, same option:**

  | Input | Output |
  | :-- | :-- |
  | `double z = 0x1.ep0;` | `Unexpected error (Failure("int_of_string"))` |
  | `double x = 1.5d;` with `-machdep gcc_x86_64` | `Unexpected error (Invalid_argument("Z.of_substring_base: invalid digit"))` |
  | `float i = INFINITY;` or `float n = NAN;` with `<math.h>` | the same `Invalid_argument` |

- **Frama-C's own `<float.h>` is enough** (reviewer's run): `DBL_MAX` gets the real value
  `8.09609013229e+304`, and `FLT_MAX` crashes (`Failure("int_of_string")`). `HUGE_VAL` crashes
  like `INFINITY`.
- **Cause (read by the subagent):** `src/lib/arithmetic/rational.ml` lines 33-62,
  `Rational.of_string`, splits on `e` (also a hexadecimal digit) and on `.`, and knows no `0x`
  form and no `d` suffix. Called from
  `plugins/eva/src/values/non_integer_arithmetic/IEEE754.ml` lines 580-583.
- **Weight:** Frama-C labels the domain experimental. It is the closest sibling of 42 and 43: a
  third parser for the same text.
- **Second opinion (`v5-text`): confirmed, and worse: a sure alarm is lost.** The first report
  saw no changed alarm. Parent re-ran on `master`:

  ```c
  #include <float.h>
  #include "__fc_builtin.h"
  int t[2];
  int main(void) {
    double x = Frama_C_double_interval(1e305, 1e306);
    double m = DBL_MAX;
    int i = 0;
    if (x < m) i = 2;        /* always taken */
    t[i] = 1;                /* out of bounds */
    return i;
  }
  ```

  - `frama-c -eva nv4.c`: `accessing out of bounds index. assert i < 2;`,
    `1 of them is a sure alarm (invalid status)`.
  - `frama-c -eva -eva-domains numerors nv4.c`: `NON TERMINATING FUNCTION`,
    `4 statements reached (out of 7)`, `0 alarms generated by the analysis`.
  - **Mechanism (read):** the domain reduces on comparisons (`IEEE754.ml` 651-667), so a wrong
    real value makes a live branch dead.
  - **The case against:** the manual says "This domain is experimental and should only be used
    on toy examples", and each run prints a warning. That lowers the priority; an opt-in domain
    should still not remove alarms.

### H16. WP: a `strategy` timeout with a suffix

```c
/*@ lemma dummy: \forall integer i; i < 0 ==> i < 1; */
/*@
  strategy S: \prover("Alt-Ergo", 2u);
  proof S: dummy;
*/
```

- **Command:** `frama-c -wp -wp-timeout 5 strat_int.i`
- **Output:** `Frama-C aborted: internal error (Typechecking ACSL extension strategy raised
  exception Failure("int_of_string")).` With `2.5f`: `Failure("float_of_string")`.
- **Cause (read by the subagent):** `plugins/wp/src/ProofStrategy.ml` lines 159 and 165 catch
  `Invalid_argument`, and `int_of_string` raises `Failure`: the intended "Invalid timeout" error
  is unreachable. The same shape as 43's handler.
- **Second opinion (`v5-text`): confirmed** (reviewer's run, both versions). `2U`, `2L` and
  `99999999999999999999` (no suffix) fail the same way; `2.5d` fails like `2.5f`. `2`, `010`,
  `0x10`, `0b11`, `2.5`, `1e2` and `0x1p1` are accepted, and `-1` gets a clean error. 25 other
  `strategy` and `proof` forms are clean. **Fix direction:** catch `Failure _`.

### H17. WP: `-wp-time-margin` is not checked

- **Command:** `frama-c -wp -wp-rte -wp-timeout 5 -wp-time-margin 1s margin.c`, on any function
  with a goal that a prover closes.
- **Output:** `Unexpected error (Failure("float_of_string"))`.
- **Cause (read by the subagent):** a `String` option (`wp_parameters.ml` line 846) read with an
  unguarded `float_of_string` (`VCS.ml` line 132, `ProofEngine.ml` line 598).
- **Second opinion (`v5-text`): confirmed** (reviewer's run, both versions). The error comes
  after the provers ran, with exit status 125 and no `Proved goals` summary. `abc` fails like
  `1s`; `nan`, `inf`, `0x10` and `1_0` are accepted silently. The WP manual writes "Default is
  5s", so `1s` is a natural thing to type; the code's default is `0.5`
  (`wp_parameters.ml` 849), so the manual is out of date too.

### Read, not run (`regex`)

- `parameter_builder.ml` 1801-1838: a one-character value before another value in a multiple map
  (`octagon:f:g`) is read as the single value `f:g`. It ends in a clean "no function" error.
- `parameter_builder.ml` 1048-1049: an escaped leading `+`, `-` or `@` is recognised in the first
  word of a comma-separated collection only, although the printer escapes every word.
- `file.ml` 403-408: a `-cpp-command` with a literal `%d` and no `%i`/`%o` never gets the input
  and output files appended.
- `eva_annotations.ml` 126, 173, 296: `//@ slevel 010;` is read as 10, not 8.

## Frama-C's libc (L1 to L6)

Found by `libc`, which generated a caller for every function of `share/libc` (63 files) and ran
WP, Eva and E-ACSL on them. The parent re-ran all six on plain `master`; `v6-libc` confirmed all
six on both versions and corrected several. Line numbers of `share/libc` are `master`'s.

### L1. WP treats a `void` object as an `int`

```c
char buf[8];
void bl_8(void)  { void *p = buf; //@ assert \block_length(p) == 8;
}
void bl_32(void) { void *p = buf; //@ assert \block_length(p) == 32;
}
void shift_4(void)  { void *p = buf; //@ assert (char *)(p + 4) == buf + 4;
}
void shift_16(void) { void *p = buf; //@ assert (char *)(p + 4) == buf + 16;
}
```

- **Default `Typed` model** (`frama-c v_bl2.c -wp -wp-fct bl_32`; parent re-ran, both versions):
  `bl_32` is `Proved goals: 3 / 3` and `bl_8` is Unknown. The goals are
  `Malloc_0[G_buf_22] = 8` for the false one and `Malloc_0[G_buf_22] = 2` for the true one: the
  length is counted in units of `sizeof(int)`. `\block_length((char *)p) == 8` is proved.
- **`Bytes` model** (`-wp-model Bytes -wp-prover none -wp-print`; parent re-ran): `shift_16` is
  `Prove: true.` and `shift_4` is `Prove: false.` Under `-machdep x86_16` the factor is 2
  (reviewer's run), so it is `sizeof(int)`. Under `Typed` the shifts are right.
- **With Frama-C's own libc** (`mempcpy`, `string.h:148`, `ensures \result == dest + n`):

  ```c
  #define _GNU_SOURCE
  #include <string.h>
  /*@ requires \valid(d + (0 .. 7)) && \valid_read(s + (0 .. 1));
      requires \separated(d + (0 .. 7), s + (0 .. 1)); */
  void f(char *d, const char *s)
  {
    void *r = mempcpy(d, s, 2);
    //@ assert wrong: (char *)r == d + 8;
  }
  ```

  `frama-c mempcpy2.c -wp -wp-model Bytes`: `Proved goals: 6 / 6`, `wrong` included (parent
  re-ran). Under `Typed`, `wrong` times out.
- **Truth:** gcc gives `sizeof(void) = 1`, `(char *)(p + 4) == buf + 4`, and
  `mempcpy(d, s, 2) == d + 2`. ACSL gives `\block_length` the signature `void* -> size_t`.
- **The case against, which holds only in part:** arithmetic on `void *` is a GNU extension. But
  the kernel accepts `p + 1` in ACSL without a warning, Frama-C's own libc relies on it, and
  `\block_length` has no such defence. WP prints `Warning: void object`, a plain log line: the
  false goals are reported proved with no flag, where other WP limitations mark the goal
  ("Degenerated", "Stronger").
- **Cause, confirmed:** `plugins/wp/src/ctypes.ml:316-318`:
  `| TVoid -> WpLog.warning ~current:true "void object" ; C_int (c_int IInt)`.
- **Other libc clauses that reach a `void` object under WP:** `rawmemchr`
  (`string.h:113,115,118`, `\block_length(s) - 1`; no wrong proof obtained) and `pthread_exit`
  (`pthread.h:373`, not tested). `memchr`, `memrchr` and `bsearch` cast to `char *` first.
- **For the pipeline:** WP runs under `Typed` by default and retries under `Bytes` on union and
  pointer-cast obstacles. Both models are concerned: `Typed` by a contract that sizes a
  `void *` buffer with `\block_length`, `Bytes` by a `void *` shift in an annotation. See the
  troubleshooting entry in
  [`../../troubleshooting/wp-and-guardrail.md`](../../troubleshooting/wp-and-guardrail.md).

### L2. `pclose`: `\false` is provable after any call

```c
#include <stdio.h>
int run(void)
{
  FILE *p = popen("ls", "r");
  if (p == NULL)
    return -1;
  pclose(p);
  //@ assert wrong: \false;
  return 0;
}
```

- **Command:** `frama-c pclose1.c -wp -wp-prop wrong` (parent re-ran)
- **Output:** `Proved goals: 1 / 1`, by Qed. The only hint is
  `Warning: No definition for 'is_open_pipe' interpreted as reads nothing`.
- **Reviewer's runs:** a full run with `-wp-rte` gives `7 / 7`. `-wp-smoke-tests` does catch it
  (`[Failed] (Doomed) ..._wp_smoke_dead_call`).
- **Cause, confirmed:** `share/libc/stdio.h:607-634`. The contract has
  `requires open_pipe: is_open_pipe(stream);`, `assigns \result \from indirect:*stream;` and
  `ensures closed_stream: !is_open_pipe(stream);`. Nothing the predicate could read is assigned,
  so both clauses speak of the same state.
- **Two defects (reviewer's runs on copies of the contract):** the contract contradicts itself
  under plain ACSL as soon as the predicate has a footprint, and WP makes a predicate without
  `reads` independent of the state, so assigning `*stream` alone would not repair it. The fix
  needs a `reads` clause (or a ghost table) and an `assigns` on it. `closedir` is consistent.
- **Eva is not misled** (reviewer's run): `assertion 'wrong' got status invalid`.
- **Reach:** everything after a `pclose` is provable under WP.

### L3. `sigaction`: what `oldact` receives

```c
#include <signal.h>
void h1(int s) { }
void h2(int s) { }
int main(void)
{
  struct sigaction a = {0}, b = {0}, old = {0};
  a.sa_handler = h1;
  b.sa_handler = h2;
  sigaction(SIGINT, &a, 0);      /* install h1 */
  sigaction(SIGINT, &b, &old);   /* install h2, old receives h1 */
  //@ assert true_in_c: old.sa_handler == h1;
  return 0;
}
```

- **Command:** `frama-c -eva sigaction1.c` (parent re-ran)
- **Output:** `[eva:ensures-false] FRAMAC_SHARE/libc/signal.h:252: Warning: function sigaction:
  this postcondition evaluates to false in this context.`, then `NON TERMINATING FUNCTION`; no
  assertion is evaluated.
- **One call is enough** (parent re-ran, both versions): `struct sigaction b = {0}, old = {0};`
  then `sigaction(SIGINT, &b, &old);` gives the same, `4 statements reached (out of 7)`.
- **Other symptoms (reviewer's runs):** after installing `h1`, a query with a null `act` makes
  `old.sa_handler == h1` invalid; `signal(SIGINT, h1)` followed by `sigaction` with `oldact`
  stops too. The common save-and-restore pattern is dead code for Eva.
- **Cause, two clauses of `share/libc/signal.h`:** line 247,
  `assigns *oldact \from &__fc_sigaction;`, gives the address of the table where its content
  `__fc_sigaction[signum]` is meant; lines 252-253,
  `\subset({*oldact}, __fc_sigaction[signum])`, read the post-state and need `\old`. The
  reviewer checked on a copy that both changes are needed, and that with both the analysis
  covers the whole function with the right handlers.

### L4. E-ACSL: `typing was not performed` on `stpncpy`, `strlcat` and a quantifier

```c
#include <string.h>
int main(void)
{
  char d[4];
  stpncpy(d, "ab", 4);
  return 0;
}
```

- **Command:** `frama-c r_stpncpy.c -e-acsl -then-last -print -ocode out.c` (parent re-ran)
- **Output:** `[e-acsl] Failure: typing was not performed on construct 1`, internal error, exit
  code 4. The same for `strlcat(d, "ab", 8)`.
- **Without the libc:** `assert \forall integer i; strlen(s) <= i < 3 ==> i >= 0;` fails with
  `construct 0`.
- **Second opinion: two paths, and the clauses first blamed are not established.**
  - Path A, the quantifier: a logic function without definition in a quantifier's bound. Typing
    a guard raises "not yet supported", so the goal is never typed, and the translation then
    looks up an untyped constant (`typing.ml:844-850`). A defined function does not crash.
  - Path B, both libc reproducers: the constant of an RTE guard under `\at` was never typed
    (`translate_ats.ml:490`). Which clause of `stpncpy` starts it is not identified.
  - **For `strlcat`, it is `bounded_result`** (added on 2026-11-18 by the session that drafted
    package 44, [`./frama-c-libc-strlcat-contract.md`](./frama-c-libc-strlcat-contract.md)): with
    that clause alone rewritten under `\old` as in 44's patch, or removed, `frama-c -e-acsl` on a
    `strlcat` call exits 0 on `master` `b80fcac74f`, where it exits 4 with this failure before;
    rewriting only the `assigns` of `dest` changes nothing. With the whole patch it exits 0 on
    `34.0~beta` too. The patch hides the E-ACSL defect for `strlcat`; it does not fix it.
  - **`e-acsl-gcc` needs `-L` to show it** (same session, both versions): by default the wrapper
    passes `-no-frama-c-stdlib`, so glibc's `<string.h>` is parsed and `strlcat` has no
    contract; `e-acsl-gcc -c` exits 0. `e-acsl-gcc -L -c` on the `strlcat` reproducer ends with
    this failure and `e-acsl-gcc: fatal error: aborted by Frama-C` (exit code 1).
- **Not #2806 (package 16), by reading:** !37 changes the lookup key of three functions through
  the normalizer; here the failing key is a constant, which the normalizer does not replace.
  Package 16 needs a defined function that reads memory, and that kind does not crash here.
  Only a build of !37 can confirm.

### L5. `syslog` with only `<syslog.h>` loses its preconditions

```c
#include <syslog.h>
int main(void)
{
  char buf[2] = {'a', 'b'};          /* not a string: no terminating 0 */
  syslog(LOG_ERR, "%s", buf);
  return 0;
}
```

- **Command:** `frama-c -eva syslog1.c` (parent re-ran)
- **Output:** `[kernel:libc:frama-c] Warning: Unable to locate ACSL predicate valid_read_string
  which should be in the Frama-C LibC. Correct specifications can't be generated.`, then
  `0 alarms`. With `#include <stdio.h>` added, Eva reports
  `precondition valid_read_string(param2) got status invalid`.
- **Cause, confirmed:** `share/libc/syslog.h:11-14` does not include
  `__fc_string_axiomatic.h`, and the Variadic plug-in looks the predicate up by name. The
  generated specification is only `assigns \nothing;`.

### L6. Minor: `getaddrinfo` makes E-ACSL print internal `Failure` lines

- **Reduced:** `ensures (\result == 0 && \fresh(*res, 4)) || \result == 1 || \result == 2;`
- **Output:** lines `[e-acsl] Failure: Interval inference was not performed on construct
  \result` (2 on the reduction, 18 on a real `getaddrinfo` call), then the expected "not yet
  supported", exit code 0. Cosmetic; at most a line in a report on L4.

## New candidates from the second opinion

What the reviewers found while looking for the same mistakes elsewhere. Each says who ran it.
All are also in `34.0~beta` unless said otherwise.

### N1. An enumeration constant has the enum's unsigned type, not `int` (`v2-kernel`)

```c
#include <stdio.h>
enum { N = 4 };
int a[N];
int get(int i)
{
  if (i < N)
    return a[i]; /* out of bounds for every negative i */
  return -1;
}
int main(int argc, char **argv)
{
  int i = -argc; /* -1 when run without arguments */
  printf("i=%d taken=%d\n", i, i < N);
  return get(i) != 0;
}
```

Parent's runs, with the pipeline's `-machdep gcc_x86_64`, the same on `master` and `34.0~beta`:

- **gcc, the original:** `i=-1 taken=1`. The program reads `a[-1]`.
- **`frama-c enumidx.c -machdep gcc_x86_64 -print`:** `N = (unsigned int)4` and
  `if ((unsigned int)i < N)`.
- **WP, `-wp -wp-rte -wp-fct get`:** `Proved goals: 4 / 4`. The index is proved in bounds.
- **E-ACSL as the pipeline builds it** (`e-acsl-gcc --no-constfold -c -F "-rte -machdep
  gcc_x86_64"`): the instrumented program prints `i=-1 taken=0` and does not abort. The printed
  C carries the unsigned comparison, so the monitored program takes the other branch.
- **Eva, `-eva -main get`:** two alarms (`0 <= i` and `i < N`): Eva does not reduce `i` through
  the unsigned comparison, so here it is imprecise and right. With known values it is wrong
  (reviewer's reproducer, parent re-ran):

  ```c
  enum { MAX = 10 };
  /*@ ensures wrong: \result == 0; */
  int lt(int i) { i = -1; return i < MAX; }   /* C: 1 */
  ```

  `-eva -main lt` gives `__retres ∈ {0}`, and `-wp -wp-rte` proves `wrong` (`3 / 3`). A loop
  `for (int i = -1; i < MAX; i++) n++;` runs zero times for Eva (`check n == 11` invalid).
- **Truth:** C11 6.7.2.2p3: enumeration constants "have type int". gcc gives an enumerator that
  fits `int` the type `int`, even when the enum type itself is `unsigned int`.
- **Scope:** enums without a negative member, under the default (gcc-like) representation. Also
  `-enums gcc-enums`, `-machdep x86_32` (reviewer's runs). Signed comparisons, subtractions and
  `_Generic` on an enumerator are concerned.
- **There is no sound flag.** `-enums int` gives the right answers above (WP no longer proves
  the index; E-ACSL aborts on `rte/index_bound: 0 <= i`), but it makes enum-typed objects
  signed, which is wrong the other way (parent's run): for `enum E { A, B };` and
  `enum E e = (enum E)-1;`, gcc gives `e < B` the value 0, and Eva under `-enums int` gives 1.
  gcc's rule is "the enum type is unsigned, its constants are `int`"; no option gives that.
- **Cause (read by the reviewer):** `src/kernel/internals/typing/cabs2cil.ml` 4395-4410 casts
  every item to the enum's kind, and a use of the constant takes the type of the item's value
  (5540-5544; 3521 for ACSL).
- **It is a deliberate upstream change.** Changelog, 2026-04-10: "Fix enumeration typing by
  making sure all items are of type ekind (#@1682)" (a private issue). Commit `2da90c219f`,
  merged by `7e9af986e2`, changed 121 files, mostly oracles, and its test oracle records
  `NONE = (unsigned int)0`. The comment above the code says gcc types constants "with a
  preference for unsigned types", which is wrong for values that fit `int`. A report must
  therefore argue from C11 and from gcc's behaviour.
- **Regression since 33.0: read only.** `git tag --contains 2da90c219f` lists `33.0-beta`,
  `33.0` and `34.0-beta`; the code before the commit kept each item's own expression. No
  earlier image was run.
- **Tracker:** `enum constant type`, `enumeration constant`, `enum unsigned comparison`,
  `gcc-enums`, `enumerator`, `cast-enum-item` and others: nothing public.
- **For the pipeline:** all three phases are concerned, on any target that compares or
  subtracts a signed value and an enumeration constant. See the troubleshooting entry in
  [`../../troubleshooting/kernel-and-stubs.md`](../../troubleshooting/kernel-and-stubs.md).

### N2. WP: `p + (a..b) + (c..d)` ignores an empty range (`v1-wp`)

```c
/*@ requires n == 0;
    requires \valid(p + (0 .. n-1) + (0 .. 1));
    assigns \nothing; */
void w2(int *p, int n) { /*@ check f_valid2: \valid(p); */ }

/*@ requires n == 0;
    assigns f_assigns3: *(p + (0 .. n-1) + (0 .. 1)); */
void w3(int *p, int n) { *p = 1; }

/*@ requires n == 0;
    assigns f_assigns5: *(p + (0 .. n-1) + 0); */   /* control */
void w5(int *p, int n) { *p = 1; }
```

- **Command:** `frama-c WPQ g4.c`, then with Alt-Ergo (parent re-ran on `master`).
- **Output:** `f_assigns3`: `Prove: true.` (the write to `*p` is accepted although the set is
  empty). `f_valid2`: the hypothesis is `valid_rw(Malloc_0, shift_sint32(p, 0), 1)`, and
  Alt-Ergo proves it. The control `f_assigns5` is `Prove: false.`
- **Truth:** with `n == 0` the set is empty: the `requires` says nothing about `p`, and the
  `assigns` allows no write.
- **Cause (read):** `plugins/wp/src/Cvalues.ml` 804-808, `shift_set`: two ranges are added bound
  by bound, with no emptiness condition. The same rule as H3; the singleton case is right.

### N3. WP: a constant that overflows a float format becomes an infinite "real" (`v1-wp`, `v2-kernel`)

```c
double ovf2(void) {
  double x = 1e308;
  double y = x * 10.0;   /* +inf */
  double z = x * 20.0;   /* +inf */
  //@ check f_c_plus1: y + 1.0 == z;
  //@ check f_c_twice: y + y == z + 5.0;
  return y;
}
```

- **Command:** `frama-c WPQ g2.c` (parent re-ran on `master`)
- **Output:** `Prove: true.` for both checks. In ACSL the comparison is on reals, and no real
  `r` satisfies `r + 1 == r`. Lemmas such as `(float)1e39 + 1.0 == (float)1e39` are proved
  too, and `(float)1e39 - (float)1e39 == 0.0`, which is true, is refuted (reviewer's run).
- **With a prover and `-wp-rte`** (parent re-ran): every goal that still holds such a constant
  fails with `[Why3 Error] anomaly: Invalid_argument("Wp.Cfloat.const_float")`, the RTE guards
  `is_nan_or_infinite` included. So the overflow is not reported as unproved; it is reported as
  a failure.
- **Cause (read):** `Cfloat.ml` 127-131 and 322-327 pass a non-finite value to `F.e_float`
  without a check (the `DIV` case has one); `Cfloat.ml` 242-264, `const_float`, raises on it
  during the Why3 export.
- **Weight:** the wrong proofs sit behind an overflow that RTE flags, and that guard is never
  proved. Same family as H15 and H19.

### N4. The printer writes `inf`, `-inf` and `nan` as C (`v3-print`)

```c
#include <stdio.h>
int main(void) {
  double a = 1.0 / 0.0;
  double b = -1.0 / 0.0;
  double c = 0.0 / 0.0;
  float d = 1e38f * 10;
  printf("%a %a %d %a\n", a, b, c != c, (double)d);
  return 0;
}
```

- **Command:** `e-acsl-gcc -c inf.c` (parent re-ran, both versions)
- **Output:** the generated C holds `double a = inf;`, `double b = -inf;`, `double c = -nan;`
  and `float d = inff;`; gcc stops with `'inf' undeclared` and `e-acsl-gcc` with
  `fatal error: fail to compile/link instrumented code`. The original prints `inf -inf 1 inf`.
- **`--no-constfold`** (the pipeline's build): the instrumented program runs and prints the
  same as the original.
- **`frama-c inf.c -constfold -print`** prints the same text, and `-float-print hex` too. With
  Frama-C's `<math.h>`, `double e = INFINITY;` becomes `inf` under `-constfold`.
- **Cause (read):** `cil.ml:3962-3964` folds to a non-finite constant (the comment says "might
  be infinity or NaN, but that's still a float"); the printer (`cil_printer.ml:639-647`) has no
  case for it. The same printer as H10 and H15.

### N5. `__int128` constants are printed with the suffix `LL` (`v3-print`)

- **Reproducer:** `__int128 v = ((__int128)1 << 100) + 5;` and
  `unsigned __int128 u = ~(unsigned __int128)0;`, printed in halves with `%llx`.
- **Command:** `frama-c i128.c -machdep gcc_x86_64 -constfold -print -ocode o.c`, then gcc
  (parent re-ran, both versions).
- **Output:** `__int128 v = 1267650600228229401496703205381LL;` and
  `unsigned __int128 u = 340282366920938463463374607431768211455ULL;`. gcc only warns
  ("integer constant is too large for its type"). The original prints
  `1000000000 5 ffffffffffffffff ffffffefffffffff`; the printed program prints
  `0 5 0 ffffffffffffffff`. Without `-constfold` the expressions are kept and the output is
  right.
- **Cause (read):** `cil_printer.ml:625-626` gives `IInt128` the suffix `LL`. C has no 128-bit
  literal, so the constant must be printed as an expression.
- **For the pipeline:** not concerned (`--no-constfold`).

### N6. `getpwnam_r`, `getpwuid_r`: Eva treats the success branch as dead (`v6-libc`)

```c
#include <pwd.h>
int main(void)
{
  struct passwd pw, *res = 0;
  char buf[256];
  int r = getpwnam_r("root", &pw, buf, 256, &res);
  //@ assert reached: \true;
  if (r == 0 && res) {
    //@ assert found: \true;
  }
  return 0;
}
```

- **Command:** `frama-c -eva pw.c` (parent re-ran, both versions)
- **Output:** `res ∈ {0}`, `7 statements reached (out of 11)`, one assertion evaluated: `found`
  is never reached. The only message is a "garbled mix" note on `assigns *pwd`.
- **Truth:** on success the function stores at `*result` a pointer to the caller's structure.
- **Cause (read, and checked by the reviewer on a copy):** `share/libc/pwd.h:68` and `:85`,
  `assigns *pwd, *result \from &__fc_pwd;`. `*result` does not depend on `pwd`, so
  `ensures *result == \null || *result == pwd` can only be met by `\null`. `grp.h:57` has
  `assigns *result \from grp;`, and `getgrnam_r` is right.

### N7 to N12. Literals: contrived wrong values (reviewers' runs)

| # | What | Reproducer and result | Cause (read) |
| :-- | :-- | :-- | :-- |
| N7 | A hexadecimal float literal with an `f` suffix is rounded twice (`v2-kernel`) | `float f3 = 0x1.0000010000000001p0f;` is `0x1p0` for Eva (gcc: `0x1.000002p+0`); `check f3 == 0x1.000002p0` invalid. Decimal literals are right. | `src/lib/floating_point/typed_float.ml` 424-437, `parse_hexadecimal`: `float_of_string`, then rounding to single |
| N8 | `(_Bool)lit` is dropped for a literal from 0 to 255 (`v2-kernel`) | `(_Bool)2 == 2` is valid for Eva and WP, and so are `(_Bool)x == 1` and `(_Bool)x == (_Bool)2` with `x == 2`: together 1 == 2 | `logic_utils.ml` 330-331: `fitsInInt IBool` treats `_Bool` as an 8-bit unsigned |
| N9 | ACSL adjacent string literals are concatenated as raw text (`v4-acsl`) | `sizeof("\x4" "1")` is printed `sizeof("A")`; `strlen("\x4" "1") == 2` invalid for Eva (gcc: the first byte is 4) | `logic_parser.mly` 675-681 |
| N10 | An escape the ACSL lexer does not list is kept as a backslash and a character, silently (`v4-acsl`) | `int c_e = '\e'; check c_e == '\e';` invalid; `'\e' == 23653` proved. The C lexer reads `\e` as 27 and rejects unknown escapes. | `logic_lexer.mll:569` |
| N11 | In an ACSL wide string, `8` and `9` count as octal digits (`v4-acsl`) | `L"\18"[0] == 16`: WP's goal is `w[0] = 16` (C: `\1` then `'8'`) | `logic_typing.ml:26-35` |
| N12 | The printer escapes ACSL wide strings twice (`v3-print` and `v4-acsl`, independently) | `sizeof(L"\n\t") == 3*sizeof(wchar_t)` is valid on the original and invalid on the file that `-print -ocode` writes | `cil_printer.ml:2398-2405`: an escaped character goes through `%S` |

### N13 to N20. Loud failures and minor ones (reviewers' runs unless said)

| # | What | Reproducer and result | Cause (read) |
| :-- | :-- | :-- | :-- |
| N13 | The C lexer rejects universal character names (`v3-print`) | A wide literal with a 4-digit or 8-digit universal character name is valid C99; Frama-C answers `Unrecognized escape sequence`. This is why H12's output cannot be read back. | `clexer.mll:269-286`: `scan_escape` has no case for them |
| N14 | The wide-string printer does not protect trigraphs (`v3-print`) | `L"a?\?!b"` is printed `L"a??!b"`; `e-acsl-gcc` compiles with `-std=c99`, gcc converts the trigraph, and `w[3]` is 0 instead of `'!'` | `escape.ml:61-63` creates a fresh trigraph state per character |
| N15 | `//@ loop unroll 1/0;` (`v5-text`) | `frama-c -eva`: `Unexpected error (Division_by_zero)`. Reachable from a macro that is 0. | `logic_utils.ml` 2388, from `partitioning_parameters.ml` 84 |
| N16 | `-wp-par 0` (`v5-text`) | `Unexpected error (Invalid_argument("Prove_client.set_max_running_provers"))` | an unbounded `Int` option (`wp_parameters.ml` 862-870) |
| N17 | Custom machdep with `sizeof_int: 0` (`v5-text`) | `Unexpected error (Invalid_argument("Z.shift_left: count argument must be positive"))` | not located |
| N18 | C side: an out-of-range escape in a narrow character constant is accepted silently (`v4-acsl`, `master` only) | `int c1 = '\777';` is 511 without a message; gcc warns and gives -1. C11 6.4.4.4p9 is a constraint. | `cil.ml:4145-4156`, next to H8 |
| N19 | An unbalanced quote in an annotation ends in an internal error (`v4-acsl`; parent re-ran on `master`) | `//@ check o5: "abc == 1;` prints a user error and "Some annotations will be kept as is", then `Failure: too few annotations in result file while preprocessing annotations`, exit 4. The same for the C23 digit separator `1'000`. | `logic_preprocess.mll:90-96` and 122-128: the promised fallback does not work |
| N20 | `<wchar.h>` alone: `wprintf` cannot find `__fc_stdout` (`v6-libc`) | `Unable to locate global __fc_stdout which should be in the Frama-C LibC.` The precondition is still generated; only the effect on the stream is missing. | lesser sibling of L5 |

### N21. Seen in passing

- **Ran by a reviewer, minor:** `//@ check 10uu == 10;` aborts Frama-C even with
  `-kernel-warn-key annot-error=active` (`cil.ml:2654-2657`); `_Generic` on an enum-typed object
  selects `int` whatever the enum's kind; `#if '\377' > 0` is false under `-machdep ppc_32`;
  `-load-library nosuch`, `-time /proc/nonexistent/t` and
  `-wp-why3-extra-config /nonexistent.conf` end in an unexpected or internal error; a wide
  escape of 2^32 or more stops `-print` (`escape.ml:71`).
- **Read only:** `plugins/server/src/server_socket.ml` 136, `int_of_string` under
  `with Invalid_argument _` (the mismatch of H16, on bytes from a socket client);
  `Vset.is_empty` on a comprehension (`Vset.ml` 182) compares the element with the empty set;
  WP prints `-0.0` as `.0` (no wrong proof obtained); a newline inside a `-D` value of a
  compilation database.

## Checked, nothing found

So that the next hunt does not redo it:

- **`models`:** 240 ground integer lemmas (ACSL `/`, `%`, shifts, bitwise operators beyond 2^64,
  casts) under four models; about 1,500 symbolic integer lemmas against the rules of `Cint.ml`
  (truth by sampling); 240 C functions computing constants under eight memory and arithmetic
  models with `-wp-rte`. No mismatch outside the `real` model's documented meaning. Not reached:
  `Cint.ml` 870-1762, `Cstring.ml`, `LogicBuiltins.ml`, most of `Vlist.ml`.
- **`syntax`:** ACSL integer literals (binary, octal, hexadecimal, every suffix, beyond 64 bits)
  under WP and Eva; E-ACSL's big integers. Not done: Aorai's literal conversion, `\u` in ACSL.
- **`regex`:** every `Str.string_match` and `Str.search_forward` site of `src/` and `plugins/`,
  and the `int_of_string`, `float_of_string`, `Z.of_string`, `Q.of_string` and `Scanf.sscanf`
  calls on user text. Not reached: WP driver templates (`plib.ml` 156), proof-script JSON.
- **`v1-wp`:** `Vlist.ml` (25 lemmas on `\nth`, `\length`, `\repeat`, `\concat`), the rest of
  `Vset.ml` (16 lemmas), Qed's `e_div` and `e_mod`, mixed integer and real comparisons above
  2^53, `float` and `double` operations on constants. Not done: `Cint.ml` 870-1762,
  `Cstring.ml`, `LogicBuiltins.ml`, the tactics, models other than the default.
- **`v2-kernel`:** the typing of 40 integer literals through `_Generic` (identical to gcc on
  `x86_64`; by hand on three other machdeps), decimal float literals against gcc (ties,
  denormals, overflow), wide character constants, string bytes above 127, the integer branch
  of `numeric_coerce`, the casts that RTE generates. Not reached: E-ACSL runs for H4, H5, H8.
- **`v3-print`:** `-print -ocode` without `-constfold` (every floating constant keeps its text),
  about 80 integer expressions with and without `-constfold` (`INT_MIN`, `LLONG_MIN`, enum
  constants, casts of negative constants), narrow strings and character constants, designated
  initializers, compound literals, bit-fields. Not done: Aorai, slicing, `u""`/`U""` literals.
- **`v4-acsl`:** simple escapes, octal escapes of one to three digits, hexadecimal of one and
  two digits, ACSL integer literals with every suffix, the tokens the logic lexer must split
  (`(0..3)`, `1.e0`), macros and quotes in the annotation preprocessor. Not covered: a string
  holding `*/` in an annotation, ghost code.
- **`v5-text`:** 27 Eva annotation forms, about 45 WP option values, 25 `strategy` and `proof`
  forms, kernel options with garbage values, and a scan of `src/` and `plugins/` for a `try`
  whose handler names the wrong exception (a window of four lines, so not complete). Not
  covered: acsl-importer inputs, proof-script JSON, WP driver files.
- **`v6-libc`:** `\false` after every libc call under WP (only `pclose`, beside the functions
  that do not return), every `ensures` that reads `__fc_*` state, and about 60 `\from &__fc_x`
  clauses (only `signal.h:247` and `pwd.h:68,85` are wrong; `utmp.h:124,131,139` looks plausible
  and was not run).

## Where the files are

The reproducers of H1 to H19, L1 to L5 and N1 to N4 and N6 are quoted in full above. N5 and N7
to N21 are summaries: their full reproducers, with every output and the tracker search words,
are in the six reviewers' reports. Those were saved as `report-v1-wp.md` to `report-v6-libc.md`
in a scratch folder of the session that wrote this file, which is not kept; they can be
extracted again from that session's transcript (the hand-back messages of the six reviewer
subagents). Copy a reproducer here before drafting a package from one of those entries. The images are
`framac-master-audit:b80fcac` (plain `master` `b80fcac74f`) and `framac-analysis:latest`
(`34.0~beta`).
