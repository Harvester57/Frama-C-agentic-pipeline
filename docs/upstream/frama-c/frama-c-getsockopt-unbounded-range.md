# Frama-C libc: `getsockopt` precondition uses an unbounded range (unsatisfiable for Eva, rejected by WP)

**Filed upstream on 2026-11-15:** issue [#2799](https://git.frama-c.com/pub/frama-c/-/work_items/2799), merge request [!30](https://git.frama-c.com/pub/frama-c/-/merge_requests/30).

Draft bug report for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).

**Filing package:** [issue](./filing/04b-libc-getsockopt-unbounded-range-issue.md), [MR](./filing/04b-libc-getsockopt-unbounded-range-mr.md), [reproducer](./repro/04b-libc-getsockopt-unbounded-range.sh), [patch](./patches/04b-libc-getsockopt-unbounded-range.patch)

## Summary

In `share/libc/sys/socket.h`, behavior `other_options` of `getsockopt` requires

```c
requires optval_null_or_valid:
  optval == \null || \valid(((char*)optval)+(0..));
```

The range `(0..)` has no upper bound, so the precondition requires an infinitely large
valid block, which no object satisfies. Every call with a non-null `optval`, other than
`SOL_SOCKET`/`SO_ERROR`, is therefore rejected:

- **Eva** reports the precondition as **Invalid** on correct calls, considers the call
  non-terminating, and analyses nothing after it in the caller (the rest of the function
  becomes dead code, so alarms there are silently missed).
- **WP** aborts: `User Error: Invalid infinite range (global L_opt_402)+(0..)`, so no
  function calling `getsockopt` can be proved at all.

The sibling `setsockopt` already bounds its buffer correctly:
`\valid_read(((char *)optval)+(0..optlen-1))`.

## Versions

- Reproduced on `master` at `3dff90fc70` (2026-11-13, `35.0~~dev (Bromine)`) and on
  `34.0~beta (Selenium)`, Eva and WP, with
  [`./repro/04b-libc-getsockopt-unbounded-range.sh`](./repro/04b-libc-getsockopt-unbounded-range.sh)
  (2026-11-15). The contract is at `share/libc/sys/socket.h:377-408` (clause at 397-398).
- The same text is in the public GitHub snapshot up to 20.0 (Calcium, 2019), so the
  issue is at least five years old.
- The same contract also aborts E-ACSL under `e-acsl-gcc -L`; see
  [frama-c-eacsl-unbounded-range-abort.md](./frama-c-eacsl-unbounded-range-abort.md).

## Reproduction

`caller.c`:

```c
#include <sys/socket.h>
#ifndef OPTLEN
#define OPTLEN sizeof(int)
#endif
/*@ requires 0 <= fd < __FC_MAX_OPEN_SOCKETS; */
int get_opt(int fd) {
  int opt;
  socklen_t olen = OPTLEN;
  return getsockopt(fd, 270 /* SOL_NETLINK */, 1, &opt, &olen);
}
int main(void) { return get_opt(3); }
```

```text
$ frama-c caller.c -eva
[eva:alarm] caller.c:9: Warning:
  function getsockopt, behavior other_options: precondition 'optval_null_or_valid' got status invalid.

$ frama-c caller.c -wp -wp-fct get_opt -wp-model Bytes
[wp] FRAMAC_SHARE/libc/sys/socket.h:398: User Error:
  Invalid infinite range (global L_opt_402)+(0..)
[kernel] Plug-in wp aborted: invalid user input.
```

The call is correct: `optval` points to a 4-byte object and `*optlen == 4`, and
getsockopt(2) writes at most `*optlen` bytes (POSIX: a longer value "shall be silently
truncated"). Any level/option other than `SOL_SOCKET`/`SO_ERROR` triggers it
(`SO_RCVBUF`, `TCP_INFO`, `SO_PEERCRED`, `SOL_NETLINK` options, ...).

## Fix

Patch: [`./patches/04b-libc-getsockopt-unbounded-range.patch`](./patches/04b-libc-getsockopt-unbounded-range.patch),
one commit on `fix/libc-getsockopt-range` from `3dff90fc70`, "[libc] getsockopt: bound optval by
*optlen". It bounds the buffer by `*optlen`, as `setsockopt` does with `optlen`
(`socket.h:551`) and `getsockname` with `*address_len` (`socket.h:361`), in three places:

- `requires optval_null_or_valid: optval == \null || \valid(((char*)optval)+(0 .. *optlen-1));`
- the default `assigns` (line 380) and the `other_options` `assigns` (line 399):
  `((char*)optval)[0 .. *optlen-1]`.

`*optlen == 0` gives an empty range (valid), a null `optval` stays allowed, and `so_error` is
untouched. Regression test: `tests/libc/socket_h.c` gets two calls through `other_options`
(`SO_RCVBUF`, with a 4-byte `int` and with a null `optval`) and `socket_h.0.res.oracle` is updated.
On `master` the first one is `invalid` and `main` becomes `NON TERMINATING`; with the patch both are
valid, and the null call gets the same `Completely invalid destination for assigns clause ...
Ignoring.` message as the existing null `recvfrom` call of the test.

## Validation of the fix

Built on `3dff90fc70` with the patch (image `framac-master-audit:3dff90f`), 2026-11-15, with the
reproducer:

| Check | `master` `3dff90fc70` | 34.0~beta | Patched |
|---|---|---|---|
| Eva, correct call | `optval_null_or_valid` Alarm, `NON TERMINATING FUNCTION` | same | Valid, `r ∈ {-1; 0}` |
| Eva, `*optlen` (8) larger than `optval` (4 bytes) | Alarm | same | Alarm (as it should) |
| WP (`-wp-model Bytes`), `-wp-fct get_rcvbuf` | `Invalid infinite range (global L_opt_402)+(0..)`, aborted | same | 8/8 goals proved |
| ptests `tests/libc` (244 results) | — | — | only `socket_h.0.res.oracle` changes (new calls), promoted; rerun clean |
| `git diff --check` | — | — | clean except trailing spaces in the promoted oracle lines, as in the existing oracle (36 such lines on `master`) |

Earlier check on 34 (contract declared in place of the stock one, same program; `-DOPTLEN=8`
makes the caller claim 8 bytes for a 4-byte `int`):

| Program | Stock libc | Patched |
|---|---|---|
| Eva, correct call | precondition Invalid | 7/7 preconditions valid |
| Eva, `*optlen` (8) larger than `optval` (4 bytes) | Invalid | Invalid (`optval_null_or_valid`), as it should be |
| Eva, `optval == NULL` | valid | valid |
| Eva, `SOL_SOCKET`/`SO_ERROR`, correct | valid | valid (behavior unchanged) |
| Eva, `SO_ERROR` with `*optlen == 8` | — | Invalid (`optlen_value`), unchanged |
| WP (`-wp-model Bytes`), correct call | aborts: invalid infinite range | 8/8 goals proved |
| WP (`Bytes`), `*optlen` 8 > buffer | aborts | `optval_null_or_valid` not proved (expected) |
| WP (`Bytes`), `SO_ERROR` | aborts | 8/8 goals proved |

With the default Typed model, the patched precondition times out on the correct call,
because of the `int *` to `char *` cast (a known Typed limitation), not the contract.

## Other occurrences

Re-checked on `master` `3dff90fc70` (2026-11-15) by scanning every ACSL clause under
`share/libc` for a range without an upper bound, outside `assigns`, `\from` and `reads`. The
earlier claim that the `getsockopt` clause is the only one was wrong. The scan finds six:

| Function | Clause | Satisfiable? |
|---|---|---|
| `getsockopt` | `sys/socket.h:397-398`: `requires optval_null_or_valid: ... \valid(((char*)optval)+(0..))` | no (this issue) |
| `strtok_r` | `string.h:353-355`: `requires separation: \separated(..., *saveptr+(0..))` | yes |
| `wcschr` | `wchar.h:109-110`: `ensures ... \subset(\result, wcs+(0..))` | yes |
| `wcspbrk` | `wchar.h:200-201`: same `ensures` | yes |
| `wcsrchr` | `wchar.h:208-209`: same `ensures` | yes |
| `wcsstr` | `wchar.h:225-226`: `ensures ... \subset(\result, haystack+(0 .. ))` | yes |

Only `getsockopt` is unsatisfiable. On a `strtok_r` caller and a `wcschr` caller, Eva validates the
`separation` precondition and WP (`-wp-model Bytes`) proves all goals (8/8 and 3/3). E-ACSL aborts
on such ranges under `e-acsl-gcc -L` (checked for `strtok_r`, `getsockopt` and `wcschr`); see
[frama-c-eacsl-unbounded-range-abort.md](./frama-c-eacsl-unbounded-range-abort.md).

The other open ranges (`s[0..]` in `stdio.h`, `argz.h`, `pwd.h`, `sys/stat.h`, `sys/uio.h`,
`recvmsg`, the `reads` of `strlen`/`wcslen`, ...) are in `assigns`/`\from`/`reads` clauses, where
an over-approximation is sound. The `assigns` range of `getsockopt` itself was one of those; the
patch bounds it for precision.
