# [libc] getsockopt: bound optval by *optlen

- Source branch: `fix/libc-getsockopt-range` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `3dff90fc70`. Patch: [`../patches/04b-libc-getsockopt-unbounded-range.patch`](../patches/04b-libc-getsockopt-unbounded-range.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #2799.

## Problem

In behavior `other_options` of `getsockopt` (`share/libc/sys/socket.h`), the precondition
`optval == \null || \valid(((char*)optval)+(0..))` has an unbounded range, so no object satisfies
it. Every call with a non-null `optval`, other than `SOL_SOCKET`/`SO_ERROR`, is rejected: Eva
reports the precondition invalid and treats the call as non-terminating, and WP aborts with
`Invalid infinite range`.

## Change

Bound the range by `*optlen`, as `setsockopt` does with `optlen` and `getsockname` with
`*address_len`:

- `requires optval_null_or_valid: optval == \null || \valid(((char*)optval)+(0 .. *optlen-1));`
- the default `assigns` and the `other_options` `assigns` on `optval` become
  `((char*)optval)[0 .. *optlen-1]`.

A null `optval` stays allowed, `*optlen == 0` gives an empty range, and behavior `so_error` is
unchanged.

Regression test: `tests/libc/socket_h.c` gets two calls through `other_options`
(`SOL_SOCKET`/`SO_RCVBUF`), one with a 4-byte `int` and one with a null `optval`; the oracle
`tests/libc/oracle/socket_h.0.res.oracle` is updated. On `master` the first call gets
`precondition 'optval_null_or_valid' got status invalid` and `main` becomes non-terminating. With
the patch both preconditions are valid; the null call gets the same
`Completely invalid destination for assigns clause ... Ignoring.` message as the existing null
`recvfrom` call of that test.

## Testing

On `3dff90fc70` (Debian 13, OCaml 5.5 switch), with the patch installed:

| Check | `master` | Patched |
|---|---|---|
| Eva, correct call (4-byte `int`, `*optlen == 4`) | `optval_null_or_valid`: Alarm, `NON TERMINATING FUNCTION` | Valid, `r ∈ {-1; 0}` |
| Eva, `*optlen == 8` on a 4-byte `int` | Alarm | Alarm (as it should) |
| WP `-wp-model Bytes`, `-wp-fct get_rcvbuf` | `Invalid infinite range (global L_opt_402)+(0..)`, aborted | `Proved goals: 8 / 8` |

- ptests `tests/libc` (244 test results): only `socket_h.0.res.oracle` changes (the new calls),
  promoted; the rerun passes. `tests/variadic` and `tests/pretty_printing` do not use the header.
- `git diff --check`: clean except trailing spaces in the promoted oracle lines
  (`[eva:progress] `), which existing oracles have too (36 such lines in this oracle on `master`).
- `make check-lint` on the 3 changed files (`LINTCK_FILES_INPUT`, ocp-indent 1.10.0): clean.
- `make check-headers`: not run (no new file).
- Not run: `tests/fc_script` and `tests/mopsa`, whose inputs also include `sys/socket.h`. No test
  or oracle outside `tests/libc/socket_h*` mentions `getsockopt` or `optval_null_or_valid`
  (`git grep` on `3dff90fc70`).

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
