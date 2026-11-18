# [libc] strlcat: result from the pre-state, no write past n bytes

- Source branch: `fix/libc-strlcat-contract` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `b80fcac74f`. Patch: [`../patches/44-libc-strlcat-contract.patch`](../patches/44-libc-strlcat-contract.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #<issue>.

## Problem

Two clauses of the contract of `strlcat` in `share/libc/string.h` are wrong:

- **`ensures bounded_result: \result == strlen(dest) + strlen(src);`** reads the length of `dest`
  after the call. `strlcat` returns the length of the string it tried to create: the length of
  `dest` before the call, or `n` when `dest` has no NUL within its first `n` bytes, plus the
  length of `src`.
  - Eva: with `dest` holding `"abcdef"`, `src` `"x"` and `n` 3, the result is `{7}`; the function
    returns 4. Every precondition is valid and there is no alarm.
  - WP: a caller that appends `"cd"` to `"ab"` gets `\result == strlen(d) + strlen(s)` proved
    in its post-state; at run time the result is 4 and the sum is 6.
- **`assigns dest[strlen(dest)..n]`** includes `dest[n]`, one byte past the `n` bytes the function
  may write, and every byte up to it whatever the length of `src`. A structure field that follows
  the buffer is considered modified.

And one is too weak:

- **`requires separation`** covers `src+(0..strnlen(src, n-1))`, but the function reads `src` up
  to its NUL to compute the result. `strlcat(buf + 16, buf, 8)` on
  `char buf[32] = "0123456789abcdefghij";` writes over the NUL of `src` with every precondition
  valid.

## Change

**`share/libc/string.h`,** four clauses of `strlcat`:

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

- **Frame:** it stops at the last byte the function writes, the terminating NUL. The upper bound
  is the expression that the `separation` precondition of the same contract already uses. When
  `dest` has no NUL within `n` bytes, or `n` is 0, the range is empty.
- **Result:** stated in the pre-state, with the minimum that covers the case without a NUL within
  `n` bytes.
- **Dependencies of the result:** they named `src[0..n-1]` and not `dest`. The result depends on
  the length of both strings.
- **Separation:** the source side goes from `strnlen(src, n-1)` to `strlen(src)`. This is a
  stronger precondition for existing users; it is one line, and I can drop it from this merge
  request if you prefer.
- **Not changed:** the three other preconditions, the name `bounded_result`, and `strlcpy`, whose
  result clause is right. No clause is added on the bytes written.

**New test `tests/libc/strlcat.c`, with its oracle:** five calls under Eva, each followed by a
check: everything fits (`r == 4`), truncation (`rt == 6`), no NUL within `n` bytes (`rf == 4`),
`n == 0` (`r0 == 2`), and a structure field after the buffer (`v.next == 'Z'`). All five are valid.
A sixth call, in a branch, writes over the NUL of its source: its `separation` precondition is
invalid.

**`tests/libc/oracle/string_h.0.res.oracle`:** the existing test `string_h.c` gets more precise.

- `//@ check imprecise: strlcat_res == 6;` (line 221) was unknown and is valid. I left its name.
- Two preconditions of the next call (`valid_string_src`, `valid_string_dest`, line 222) were
  unknown and are valid.
- The final values of `strlcat_res` and of three buffers are singletons where they were
  `[--..--]`.
- Two `FRAMAC_SHARE/libc/string.h` line numbers move by two.

No other oracle changes; `tests/libc/oracle/fc_libc.0.res.oracle` is not touched, so this does not
overlap with !45 or !56.

## Testing

On a build of `b80fcac74f` with the patch (Debian 13, OCaml 5.5 switch, gcc 14.2, glibc 2.41):

- **Reproducer from the issue:**
  - `cat.c`: before, `no_nul_within_n` is invalid, `appended` and `next_kept` are unknown. After,
    the three checks are valid.
  - `append.c`: before, `Proved goals: 10 / 10`. After, the false postcondition is not proved
    (`9 / 10`, a timeout). The same caller with
    `ensures \result == \old(strlen(d) + strlen(s));` and `assigns d[0 .. 15];` was not proved
    before (8 / 10) and is proved after (10 / 10).
- **The clauses against an implementation:** WP (`-wp -wp-rte`, Alt-Ergo 2.6.4) proves a byte-loop
  `strlcat` against the contract of the header: 34 of 35 goals before (`bounded_result` is not
  proved), 35 of 35 after. One fact is admitted in that body: the two lengths do not add up past
  `SIZE_MAX`. Compiled, the same body agrees with glibc 2.41's `strlcat` on the result and on
  every byte of the buffer, for destination and source lengths 0 to 10 and `n` 0 to 14 (1815
  calls).
- **New test on master:** with `master`'s `string.h`, the new test fails (the five checks are
  unknown or invalid). With the patch it passes.
- **ptests, default configuration:** both pass with no difference:
  - `tests/libc` (123 results);
  - `plugins/e-acsl/tests` (197 results).
- **`./dev/check-files.sh -p HEAD~1`:** clean (`Lint 4 file(s)`). The new test file is also
  clang-format clean.
- **E-ACSL:** on a file that calls `strlcat`, `frama-c -e-acsl` ended with
  `Failure: typing was not performed on construct 1` (exit code 4) before the patch. With it, the
  translation ends normally (exit code 0) and reports the postcondition as not yet supported.
  `e-acsl-gcc -L` on the same file goes from `fatal error: aborted by Frama-C` to an instrumented
  program that runs to the end.
- **The stronger precondition alone:** with it or without it, `tests/libc` and
  `plugins/e-acsl/tests` give the same results for every existing test. With it, WP also proves
  that the byte-loop body leaves `src` unchanged up to its NUL (36 of 36 goals; 35 of 36
  without).
- **Not run:** the rest of `tests/`, the default ptests of the other plugins, and the cram tests.
  Two searches of the source tree say they are not concerned:
  - `strlcat` appears only in `share/libc/string.h` and in the `tests/libc` files above;
  - the patch moves the lines of `string.h` after 549 by two, and the only oracle that names one
    of them is `tests/libc/oracle/string_h.0.res.oracle`
    (`git grep -nE 'libc/string\.h:(54[7-9]|5[5-9][0-9]|[6-9][0-9]{2})\b' -- '*.oracle'`).

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
