# [libc] add the TIOCM_* modem line bits to sys/ioctl.h

- Source branch: `fix/libc-ioctl-modem-lines` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `b80fcac74f`. Patch: [`../patches/41-libc-ioctl-modem-bits.patch`](../patches/41-libc-ioctl-modem-bits.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #2830.

## Problem

`share/libc/sys/ioctl.h` defines the requests `TIOCMGET`, `TIOCMBIS`, `TIOCMBIC`, `TIOCMSET` and
`TIOCMIWAIT`, but none of the bits they read and write. Serial-port code that sets RTS or DTR, or
tests CTS or the carrier, stops at `Cannot resolve variable TIOCM_RTS`.

## Change

**`share/libc/sys/ioctl.h`:** eleven definitions, after `TIOCSER_TEMT`:

```c
#define TIOCM_LE 0x001
#define TIOCM_DTR 0x002
#define TIOCM_RTS 0x004
#define TIOCM_ST 0x008
#define TIOCM_SR 0x010
#define TIOCM_CTS 0x020
#define TIOCM_CAR 0x040
#define TIOCM_RNG 0x080
#define TIOCM_DSR 0x100
#define TIOCM_CD TIOCM_CAR
#define TIOCM_RI TIOCM_RNG
```

- These are the names that glibc 2.41 defines in `<sys/ioctl.h>` (through
  `<bits/ioctl-types.h>`), with the same values and the same two aliases.
- Linux `<asm-generic/termios.h>` also has `TIOCM_OUT1`, `TIOCM_OUT2` and `TIOCM_LOOP`. glibc's
  `<sys/ioctl.h>` does not expose them, so they are not added. I can add them if you prefer.
- Only macros are added. No declaration or contract changes, and `__fc_libc.h` is not touched.

**New test `tests/libc/sys_ioctl_h.c`, with its oracle:** an Eva test that reads the lines with
`TIOCMGET`, tests `TIOCM_CD`, `TIOCM_RI`, `TIOCM_DSR` and `TIOCM_CTS`, sets `TIOCM_DTR` and
`TIOCM_RTS` with `TIOCMSET`, `TIOCMBIC` and `TIOCMBIS`, and asserts that the nine bits together
are `0x1ff` and that the two aliases equal `TIOCM_CAR` and `TIOCM_RNG`. Both assertions are valid
and there is no alarm.

No existing oracle changes, so this does not overlap with !45 or !56, which change
`tests/libc/oracle/fc_libc.0.res.oracle`.

## Testing

On a build of `b80fcac74f` with the patch (Debian 13, OCaml 5.5 switch, gcc 14.2, glibc 2.41):

- **Reproducer from the issue:** before, `Cannot resolve variable TIOCM_RTS`. After, the file
  parses, and Eva (`-eva -main set_rts -lib-entry`) reports no alarm. The same before and after
  holds for each of the eleven names, one parse per name.
- **New test on master:** with `master`'s `sys/ioctl.h`, the new test fails
  (`Cannot resolve variable TIOCM_CD`). With the patch it passes.
- **ptests, default configuration:** all three pass with no difference:
  - `tests/libc` (123 results);
  - `tests/variadic` (69 results), whose `known/ioctl.c` includes the header;
  - `plugins/e-acsl/tests` (197 results).
- **Values:** a file of eleven `_Static_assert`s on the values above is accepted by gcc with glibc
  and by Frama-C with the patch.
- **`./dev/check-files.sh -p HEAD~1`:** clean (`Lint 3 file(s)`). The new test file is also
  clang-format clean.
- **Not run:** the rest of `tests/`, the default ptests of the other plugins, and the cram tests.
  The patch only adds macros. The tests that include the header by name are
  `tests/libc/fc_libc.c` and `tests/variadic/known/ioctl.c`, and both suites ran.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
