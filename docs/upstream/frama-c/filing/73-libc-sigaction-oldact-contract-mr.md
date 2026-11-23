# [libc] sigaction: assign *oldact from __fc_sigaction[signum] and use \old

- Source branch: `fix/libc-sigaction-oldact-contract` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `189053d4a2`. Patch: [`../patches/73-libc-sigaction-oldact-contract.patch`](../patches/73-libc-sigaction-oldact-contract.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #<issue>.

## Problem

In `share/libc/signal.h:247-253`, the `sigaction` contract assigned `*oldact` from the address
`&__fc_sigaction` (producing a garbled mix) instead of `__fc_sigaction[signum]`, and checked
`\subset({*oldact}, __fc_sigaction[signum])` in the post-state instead of
`\old(__fc_sigaction[signum])`. In Eva, installing a non-null handler while saving `oldact`
triggered `[eva:ensures-false]` and stopped propagation (`NON TERMINATING FUNCTION`), and querying
an installed handler with `act == NULL` marked `old.sa_handler == h1` invalid.

## Change

**`share/libc/signal.h`:**

- Line 247: `assigns *oldact \from __fc_sigaction[signum], indirect:signum;` (was `\from &__fc_sigaction;`).
- Line 253: `\subset({*oldact}, \old(__fc_sigaction[signum]));` (was post-state `__fc_sigaction[signum]`).

**Tests and oracles:**

- New test `tests/libc/sigaction_oldact.c` + `tests/libc/oracle/sigaction_oldact.0.res.oracle`:
  exercises single-call install with `oldact`, two-call handler replacement (`handler1` ->
  `handler2`), and query-only (`act == NULL`), verifying full reachability with no `ensures-false`
  or invalid assertions.
- Updated `tests/libc/oracle/signal_c_h.{0,1}.res.oracle`: removes the `[eva:garbled-mix:assigns]`
  warning on `*oldact`.

## Testing

Validated on a fresh build of `master` `189053d4a2` (Debian 13, OCaml 5.5 switch, gcc 14.2.0, glibc 2.41):

- **Reproducer (`73-libc-sigaction-oldact-contract.sh`):** fails before on both `189053d4a2` and
  `34.0~beta` (`RESULT: bug present (3 of 3 checks fail)`); passes after installing the patch
  (`RESULT: fixed`).
- **New test on unpatched `master`:** `tests/libc/sigaction_oldact.c` fails on unpatched `master`
  and passes with the patch.
- **ptests, default configuration:** `tests/libc` (including `fc_libc`, `signal_c_h`, and all
  `check_*` checks) passes with zero unintended oracle diffs.
- **`./dev/check-files.sh -p HEAD~1`:** clean (`exit=0`).
- **Not run:** unrelated plugin test suites outside `tests/libc`.

The analysis and fix were prepared with LLM assistance (Antigravity / Gemini); I reviewed them and
ran the reproducer and tests described above.
