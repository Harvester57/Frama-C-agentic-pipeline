# Libc: the contract of `strlcat` states the result against the destination after the call, and assigns a byte past `n`

Draft for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).
**Not filed.** Issue 44 of this folder, drafted on 2026-11-18. Filing is paused until the
maintainers answer the overview issue #2832 (see [`./README.md`](./README.md)); no branch is
pushed, and the MR text still holds `#<issue>`. The finding is listed in #2832 since the same
day (see [Filing](#filing)).

**Package:**
[issue text](./filing/44-libc-strlcat-contract-issue.md),
[MR text](./filing/44-libc-strlcat-contract-mr.md),
[reproducer](./repro/44-libc-strlcat-contract.sh) with its three C files
([Eva](./repro/44-libc-strlcat-contract.c), [WP callers](./repro/44-libc-strlcat-contract-wp.c),
[WP body](./repro/44-libc-strlcat-contract-body.c)), and
[patch](./patches/44-libc-strlcat-contract.patch) (validated on `master` `b80fcac74f`).

## Summary

`share/libc/string.h` gives `strlcat` these three clauses after its four preconditions (lines 547
to 549 on `master` and on `34.0~beta`):

```
assigns dest[strlen(dest)..n] \from indirect:n, src[0..strlen(src)];
assigns \result \from indirect:src, indirect:src[0..n-1], indirect:n;
ensures bounded_result: \result == strlen(dest) + strlen(src);
```

- **The result is stated in the post-state.** In an `ensures`, `strlen(dest)` is the length of
  the destination after the call, which already holds the appended bytes. `strlcat` returns the
  length of the string it tried to create: the length of `dest` before the call plus the length
  of `src`. And when `dest` has no NUL within its first `n` bytes, it writes nothing and returns
  `n` plus the length of `src`.
- **The frame goes one byte too far.** `dest[strlen(dest)..n]` includes `dest[n]`. The function
  writes at most `n` bytes, so the last index is `n-1`, and it stops at the terminating NUL when
  `src` is short.
- **The dependencies of the result** name `src[0..n-1]` and not `dest`. The result depends on
  the length of both strings.
- **The `separation` precondition is too weak** (a fourth clause, above these three): it covers
  `src+(0..strnlen(src, n-1))`, and the function reads `src` up to its NUL. Added to the patch on
  2026-11-18 on the owner's go-ahead ("Yes, add it"), after the measurement under
  [Related](#related-not-requested).

What follows from the first two:

| Analysis | Input | Frama-C says | Truth (gcc 14.2, glibc 2.41) |
| :-- | :-- | :-- | :-- |
| Eva | `char f[8] = "abcdef"; rf = strlcat(f, "x", 3);` | `rf ∈ {7}`, 0 alarms, every precondition valid; `check rf == 4` is **invalid** | 4 |
| Eva | `strlcat(f, "xy", 0)` | `check r0 == 2` is **invalid** | 2 |
| Eva | `char d[8] = "ab"; r = strlcat(d, "cd", 8);` | `r ∈ [1..18446744073709551615]`, check unknown | 4 |
| Eva | `struct { char d[4]; char next; } v = {"a", 'Z'}; strlcat(v.d, "b", 4);` | `{.d[1..3]; .next} ∈ [--..--]`, `check v.next == 'Z'` unknown | `'Z'` |
| WP | a caller with `ensures \result == strlen(d) + strlen(s);` and `assigns d[0 .. 16];` | **proved**, 10 / 10 | result 4, sum 6 after the call |
| WP | the same caller with `\old(strlen(d) + strlen(s))` and `assigns d[0 .. 15];` | not proved, 8 / 10 | holds |
| WP | a byte-loop `strlcat` against the contract | `bounded_result` not proved, 34 / 35 | |
| Eva | `char buf[32] = "0123456789abcdefghij"; strlcat(buf + 16, buf, 8);` | every precondition valid, 0 alarms | writes over the NUL of `src`: undefined (BSD manual) |

The two invalid checks are the serious part: Eva gives a single wrong value with no alarm, so
code that depends on the real value is dead for the analysis. The WP proof of a false
postcondition is the same defect seen from a caller.

Found on 2026-11-18 while proving reference bodies of the pipeline's own `strlcpy` and `strlcat`
contracts ([`../../../templates/fc_stubs/fc_strlcpy.h`](../../../templates/fc_stubs/fc_strlcpy.h),
[`../../../tests/test_fc_strlcpy_reference.py`](../../../tests/test_fc_strlcpy_reference.py)):
upstream's clause was first noticed by reading, then reproduced.

## What `strlcat` does

- **BSD manual, glibc 2.38 and later:** the function appends at most `n - strlen(dest) - 1`
  bytes and a NUL, and returns the initial length of `dest` plus the length of `src`. If it finds
  no NUL in the first `n` bytes of `dest`, it writes nothing and returns `n` plus the length of
  `src`.
- **Measured:** the reproducer compiles each case with gcc 14.2 and glibc 2.41 and prints what
  holds. A byte-loop body written from the manual
  ([`./repro/44-libc-strlcat-contract-body.c`](./repro/44-libc-strlcat-contract-body.c)) returns
  the same value and leaves the same 32 bytes as glibc's function for destination and source
  lengths 0 to 10 and `n` 0 to 14: 1815 calls, 0 mismatches.

## Versions

| | Result |
| :-- | :-- |
| `35.0~~dev (Bromine)`, `master` at `b80fcac74f` (image `framac-master-audit:b80fcac`) | **9 of 9 checks fail** |
| `34.0~beta (Selenium)` (image `framac-analysis:latest`) | **9 of 9 fail**, the same lines |
| `master` at `b80fcac74f` with the patch installed | `RESULT: fixed` |
| `34.0~beta` with the four clauses written into its installed `string.h` | `RESULT: fixed` |

On 2026-11-18 upstream `master` was still `b80fcac74f`.

## Reproduction

[`./repro/44-libc-strlcat-contract.sh`](./repro/44-libc-strlcat-contract.sh) runs nine checks:

- **Five with Eva** on [`./repro/44-libc-strlcat-contract.c`](./repro/44-libc-strlcat-contract.c),
  each compared with the compiled program.
- **Two with WP** on
  [`./repro/44-libc-strlcat-contract-wp.c`](./repro/44-libc-strlcat-contract-wp.c): a caller whose
  postcondition is false at run time must not be proved, and a correct caller must be.
- **One with WP** on the byte-loop body, which must be proved against the contract that comes
  with the declaration.
- **One with Eva** on
  [`./repro/44-libc-strlcat-contract-overlap.c`](./repro/44-libc-strlcat-contract-overlap.c), a
  call that writes over the NUL of its source: `separation` must be invalid. Added with the
  fourth clause.

Before, on both versions (exit code 1):

```
appended: gcc holds; eva unknown
truncated: gcc holds; eva unknown
no_nul_within_n: gcc holds; eva invalid
zero_size: gcc holds; eva invalid
next_kept: gcc holds; eva unknown
post_state_length: gcc DOES NOT HOLD (result 4, strlen(d) + strlen(s) after the call 6); wp proved 1 / 1
pre_state_length: gcc holds (result 4, strlen(d) + strlen(s) before the call 4); wp proved 8 / 10
body: wp proved 34 / 35
overlap: eva separation valid
RESULT: bug present (9 of 9 checks fail)
```

After (exit code 0):

```
appended: gcc holds; eva valid
truncated: gcc holds; eva valid
no_nul_within_n: gcc holds; eva valid
zero_size: gcc holds; eva valid
next_kept: gcc holds; eva valid
post_state_length: gcc DOES NOT HOLD (result 4, strlen(d) + strlen(s) after the call 6); wp proved 0 / 1
pre_state_length: gcc holds (result 4, strlen(d) + strlen(s) before the call 4); wp proved 10 / 10
body: wp proved 35 / 35
overlap: eva separation invalid
RESULT: fixed
```

The script passes `-eva-show-progress`: Eva prints a valid status only among its progress
messages, and the first version of the script read "not reached" for every valid check.

## Fix

[`./patches/44-libc-strlcat-contract.patch`](./patches/44-libc-strlcat-contract.patch): one commit
on `b80fcac74f`, four files, 197 added lines and 16 removed (second version, with the
`separation` precondition; the first had 155 and 15).

- **`share/libc/string.h`:**

  ```
  requires separation:
    \separated(dest+(0..\min(n-1, strlen(dest)+strlen(src))),
               src+(0..strlen(src)));
  assigns dest[strlen(dest)..\min(n-1, strlen(dest)+strlen(src))]
    \from indirect:n, src[0..strlen(src)];
  assigns \result \from indirect:dest[0..], indirect:src[0..], indirect:n;
  ensures bounded_result:
    \result == \old(\min(strlen(dest), n) + strlen(src));
  ```

  - The source side of `separation` goes from `strnlen(src, n-1)` to `strlen(src)` (second
    version of the patch).
  - The upper bound of the frame is the expression the `separation` precondition of the same
    contract already uses. It is empty when `dest` has no NUL within `n` bytes and when `n` is 0
    (`n-1` is -1 in the logic).
  - The minimum with `n` covers the case without a NUL within `n` bytes.
  - The three other preconditions and the name `bounded_result` are kept. No clause is added on
    the bytes written: Eva still gives `[--..--]` for them.
- **`tests/libc/strlcat.c`** and its oracle: the five Eva cases of the reproducer, all valid, and
  the overlapping call in a branch (`if (nondet)`), whose `separation` is invalid.
- **`tests/libc/oracle/string_h.0.res.oracle`:** the existing test gets more precise.
  - `//@ check imprecise: strlcat_res == 6;` (`string_h.c:221`) goes from unknown to valid.
  - Two preconditions of the call on line 222 go from unknown to valid.
  - `strlcat_res` and three buffers get exact final values.
  - Two line numbers of `string.h` move by two.
- **No other oracle changes.** `tests/libc/oracle/fc_libc.0.res.oracle` is not touched, so the
  patch does not overlap with !45 (26) or !56 (39). No other patch of this folder touches
  `string.h` or the `string_h` oracle.

### Validation

Run on 2026-11-18 in a container of `framac-master-audit:b80fcac` with
[`../../../tools/upstream_audit/revalidate.sh`](../../../tools/upstream_audit/revalidate.sh)
`package 44`. The whole list was run again on the second version of the patch, in a fresh
container, with the same results:

- **`git am --keep-non-patch`** applies the patch; author and committer are the GitLab noreply
  address; no file-mode change and no executable file.
- **New test against `master`'s `string.h`:** fails. `appended`, `truncated` and `next_kept` are
  unknown, `no_nul_within_n` and `zero_size` are invalid. With the patch it passes.
- **Suites, default configuration, with the patch:** `plugins/e-acsl/tests` (197 result logs) and
  `tests/libc` (123) pass with no difference.
- **`./dev/check-files.sh -p HEAD~1`:** passes (`Lint 4 file(s)`). The new test was clang-format
  clean before the commit.
- **Reproducer on the installed patched tree:** `RESULT: fixed`.
- **The snippets of the issue text** (`cat.c`, `append.c`), on `b80fcac74f`:
  - Before: the output quoted in the issue.
  - After: the three checks of `cat.c` are valid (`rf ∈ {4}`, `r ∈ {4}`, `.next ∈ {90}`), and
    `append.c` gives `Proved goals: 9 / 10` (the false postcondition times out).
- **Where `strlcat` appears upstream:** `share/libc/string.h`, `tests/libc/string_h.c` and its
  oracle. Nothing under `plugins/` or `src/`.
- **Line shift:** the patch adds two lines, so every line of `string.h` after 549 moves by two.
  37 oracles outside `tests/libc` name a line of `string.h` (E-ACSL and Eva tests); none names a
  line at or after 547
  (`git grep -nE 'libc/string\.h:(54[7-9]|5[5-9][0-9]|[6-9][0-9]{2})\b' master -- '*.oracle'`:
  two hits, both in `tests/libc/oracle/string_h.0.res.oracle`, which the patch updates).

Not run: the rest of `tests/`, the default ptests of the other plugins, and the cram tests. The
`dev` step of `revalidate.sh` passes on both sides because `tests/libc` has no `dev`
configuration; it says nothing here.

Provers: the audit image has Alt-Ergo 2.6.4, the `34.0~beta` image Alt-Ergo 2.4.3. The reproducer
uses `-wp-prover alt-ergo -wp-timeout 20` and gives the same counts with both.

## Effect on E-ACSL

On a file that only calls `strlcat`, `frama-c -e-acsl -then-last -print` ends with
`[e-acsl] Failure: typing was not performed on construct 1` and exit code 4 (both versions). It is
candidate L4 of
[`./frama-c-hunt-2026-11-18-candidates.md`](./frama-c-hunt-2026-11-18-candidates.md). With the
patched header the translation ends normally (exit code 0): the postcondition is under `\old`,
and E-ACSL reports it as not yet supported and ignores it.

- **The clause that starts it is `bounded_result`,** isolated on `master`'s header with one
  clause changed at a time:
  - only the `assigns` of `dest` rewritten: still exit code 4;
  - only `bounded_result` rewritten as in the patch: exit code 0;
  - `bounded_result` removed: exit code 0.
- L4's entry says the clause was not identified for `stpncpy`; that part is unchanged.
- The patch hides the E-ACSL defect for `strlcat`. It does not fix it: the cause is in E-ACSL.
- **`e-acsl-gcc` without `-L` never showed the failure, and that is expected.** By default the
  wrapper passes `-no-frama-c-stdlib` (read in its `bash -x` trace), so Frama-C parses glibc's
  `<string.h>`, where `strlcat` has no contract: the generated code calls `strlcat` directly,
  with no `__gen_e_acsl_strlcat` wrapper. The first version of this draft said "exits 0 before
  and after" without saying why.
- **With `-L` (Frama-C's libc) the wrapper fails like plain Frama-C** (both versions):

  | `e-acsl-gcc -L -c l4.c` | Released header | Patched header |
  | :-- | :-- | :-- |
  | exit code | 1 (`e-acsl-gcc: fatal error: aborted by Frama-C`) | 0 |
  | instrumented program | none | built, runs to the end (exit code 0) |

- **The pipeline is not concerned:** its E-ACSL builds use the host's headers
  (`-no-frama-c-stdlib`), and its own stub has no such clause in its E-ACSL branch.

## Related, not requested

- **The `separation` precondition was too weak; it is in the patch since its second version.**
  It covered `src+(0..strnlen(src, n-1))`, and the
  function reads `src` up to its NUL.
  - `char buf[32] = "0123456789abcdefghij"; strlcat(buf + 16, buf, 8);` has its four
    preconditions valid under Eva. The call writes `buf[20..23]`, which holds the NUL of `src`.
  - glibc 2.41 returns 24 and leaves `0123456789abcdefghij012`. The BSD manual says the behaviour
    is undefined when the strings overlap.
  - Eva gives `r ∈ [24..34]` before the patch and `r ∈ {24}` after.
  - WP shows the same gap: the reference body of the pipeline's stub has an assertion that `src`
    is unchanged after the copy, and WP does not prove it against upstream's contract.
  - The first version of the patch left it out, because a stronger precondition can break
    existing proofs, and the texts offered it.
  - **Measured on 2026-11-18** (container of `framac-master-audit:b80fcac`, the first version of
    the patch plus that one-line change, rebuilt):

    | Check | First version | With `src+(0..strlen(src))` |
    | :-- | :-- | :-- |
    | `tests/libc`, default configuration (123 result logs) | pass | pass, no oracle changes |
    | `plugins/e-acsl/tests`, default configuration | pass | pass, no oracle changes |
    | Eva on the overlapping call above | `separation` valid, `r ∈ {24}`, 0 alarms | `separation` **invalid**, the call does not terminate |
    | WP on the byte-loop body plus an assertion that `src` is unchanged up to its NUL | 35 / 36 (the assertion times out) | 36 / 36 |
    | Reproducer 44 and the issue's `cat.c` | fixed, 12 preconditions valid | the same |

    So no upstream test depends on the weak form. Proofs of users who call `strlcat` on
    overlapping strings would break, which is the purpose. On that result the owner said to add
    it. Both filing texts say it is one line and can be dropped if the maintainers prefer.
- **`strlcpy`:** its contract is consistent. WP proves a byte-loop body against it, 31 of 31
  goals, with one admitted fact (the bytes of `src` are initialized).
- **No clause on the bytes written,** for `strlcat` and `strlcpy` alike. The pipeline's stub
  states them (`copied`, `dst_holds_copy`); upstream's does not. Not proposed.

## Duplicates

Searched live on 2026-11-18 through the read-only API (`glab api`, issues and merge requests of
`pub/frama-c`, all states):

- `strlcat`: only #2832, the overview issue of this folder. No merge request.
- `strlcpy`: nothing.

#2832 was open with no comment that day.

## Filing

- **Not filed.** Filing is paused until the maintainers answer #2832, and this package was
  prepared without a go-ahead to file.
- **When filing:** build the branch `fix/libc-strlcat-contract` with
  [`../../../tools/upstream_audit/make_branches.sh`](../../../tools/upstream_audit/make_branches.sh)
  after checking that the container's `master` is the head upstream has that day, then
  `file_upstream.py issue 44`, `subst`, `mr 44`. If `share/libc/string.h` or `tests/libc` moved
  upstream, regenerate the two oracles.
- **The overview issue #2832 lists it** since 2026-11-18, 21:56 UTC, on the owner's request
  ("update the main discussion but don't fill a unitary issue for this yet"). Four additions
  to its description, the same in
  [`./filing/00-reports-overview-issue.md`](./filing/00-reports-overview-issue.md):
  - a dated note at the top of "Findings I have not filed";
  - a Libc row in the table of wrong-answer findings, which says a patch exists;
  - a row `44` in the Libc table of the annex;
  - one sentence in the annex row L4: for `strlcat`, the E-ACSL failure comes from this clause.
  - The issue was open with no comment just before; the stored description was read back and is
    identical to the file.

## Pipeline workaround

None is needed. [`../../../templates/fc_stubs/fc_compat_types.h`](../../../templates/fc_stubs/fc_compat_types.h)
renames libc's `strlcpy` and `strlcat`, so every Eva and WP parse of the pipeline sees only the
contract of [`../../../templates/fc_stubs/fc_strlcpy.h`](../../../templates/fc_stubs/fc_strlcpy.h),
which states the result in the pre-state and is proved for reference bodies. A target analysed
with plain Frama-C and its libc gets upstream's contract.
