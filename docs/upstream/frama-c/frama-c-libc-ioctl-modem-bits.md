# Libc: `<sys/ioctl.h>` defines `TIOCMGET` and `TIOCMSET` but not the `TIOCM_*` modem-line bits

Draft for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues). **Not filed.**
Issue 41 of this folder. Drafted on 2026-11-18.

**Package:** [reproducer](./repro/41-libc-ioctl-modem-bits.sh) with its
[C file](./repro/41-libc-ioctl-modem-bits.c). No filing texts and no patch yet.

## Summary

Frama-C's `share/libc/sys/ioctl.h` defines the modem-control requests `TIOCMGET`, `TIOCMBIS`,
`TIOCMBIC`, `TIOCMSET` and `TIOCMIWAIT`, but none of the bits these requests read and write:
`TIOCM_LE`, `TIOCM_DTR`, `TIOCM_RTS`, `TIOCM_ST`, `TIOCM_SR`, `TIOCM_CTS`, `TIOCM_CAR`,
`TIOCM_RNG`, `TIOCM_DSR`, `TIOCM_CD`, `TIOCM_RI`, `TIOCM_OUT1`, `TIOCM_OUT2`, `TIOCM_LOOP`.

Any serial-port code that toggles RTS or DTR, or reads CTS or carrier detect, then stops the parse:

```
[kernel] src/modbus-rtu.c:254: User Error:
  Cannot resolve variable TIOCM_RTS
```

With glibc, `<sys/ioctl.h>` includes `<bits/ioctl-types.h>`, which defines `TIOCM_LE` to `TIOCM_RI`.
Linux `<asm-generic/termios.h>` defines all fourteen, with the same values (x86_64 and every
architecture using the generic layout). The requests are already there, so this is a gap in the
same header rather than a missing feature: a program cannot use `TIOCMGET` without these bits.

Found on libmodbus (`run-1`, 2026-11-18): the library's only product unit (`modbus-rtu.c`,
`modbus.c`, `modbus-tcp.c`, `modbus-data.c`) failed to parse, and the pipeline fell back to gcc for
the whole library. See the `TIOCM_RTS` entry of
[`../../troubleshooting/kernel-and-stubs.md`](../../troubleshooting/kernel-and-stubs.md).

## Versions

| | Result |
|---|---|
| `35.0~~dev (Bromine)`, `master` at `95408044f7` (image `framac-master-audit:9540804`) | **all six cases fail** (`Cannot resolve variable TIOCM_*`) |
| `34.0~beta (Selenium)` (image `framac-analysis:latest`) | **all six fail**, identical output |
| `master` with the fourteen bits defined before the parse (the pipeline's workaround header, force-included) | `RESULT: fixed` |

## Reproduction

[`./repro/41-libc-ioctl-modem-bits.sh`](./repro/41-libc-ioctl-modem-bits.sh) parses
[`./repro/41-libc-ioctl-modem-bits.c`](./repro/41-libc-ioctl-modem-bits.c) once per bit
(`-DCHECK_rts`, `dtr`, `cts`, `cd`, `ri`, `dsr`), with Frama-C's own libc and with gcc. On both
versions:

```
rts: frama-c Cannot resolve variable TIOCM_RTS; gcc ok
dtr: frama-c Cannot resolve variable TIOCM_DTR; gcc ok
cts: frama-c Cannot resolve variable TIOCM_CTS; gcc ok
cd: frama-c Cannot resolve variable TIOCM_CD; gcc ok
ri: frama-c Cannot resolve variable TIOCM_RI; gcc ok
dsr: frama-c Cannot resolve variable TIOCM_DSR; gcc ok
RESULT: bug present (6 of 6 checks fail)
```

## Suggested fix

Add the fourteen definitions to `share/libc/sys/ioctl.h`, next to `TIOCMGET` and the other `TIOC*`
requests it already copies from Linux:

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
#define TIOCM_OUT1 0x2000
#define TIOCM_OUT2 0x4000
#define TIOCM_LOOP 0x8000
```

No contract changes: `ioctl` keeps its variadic specification. A ptests case would be the
reproducer's `CHECK_rts` file.

## Related, not requested

- **termios2 requests** (`TCGETS2`, `TCSETS2`, `TCSETSW2`, `TCSETSF2`, from Linux
  `<asm-generic/ioctls.h>`): the same header stops at `TCGETS`/`TCSETS`. libmodbus built with
  `HAVE_STRUCT_TERMIOS2` stops next at `Cannot resolve variable TCGETS2`. They encode
  `sizeof(struct termios2)`, a Linux UAPI type from `<asm/termbits.h>` that Frama-C's libc does not
  have, so they are left out: #2828 already asks which Linux headers are wanted.
- **The `_IO`/`_IOR`/`_IOW`/`_IOWR` encoding** is already asked in #2828's inventory.

## Duplicates

Checked on 2026-11-18, offline only (no tracker access was used for this draft):

- [`./frama-c-e-acsl-issues.md`](./frama-c-e-acsl-issues.md): no `TIOCM`, `termios` or modem entry.
- `./pub-frama-c_work_items_2026-11-09.csv`: no `ioctl`, `TIOC` or `termios` item.
- [`./frama-c-libc-linux-header-gaps.md`](./frama-c-libc-linux-header-gaps.md) (Issue 39, #2828):
  its inventory covers `<sys/ioctl.h>`'s `_IO*` macros only, not these bits.

Search the tracker live before filing. Since #2828 already asks about `<sys/ioctl.h>`, this could
also go as a note on #2828 instead of a new issue: the owner's call.

## Pipeline workaround

[`../../../templates/fc_stubs/fc_compat_types.h`](../../../templates/fc_stubs/fc_compat_types.h)
defines the fourteen bits and the four termios2 requests, each `#ifndef`-guarded, in its
`__fc_libc` branch (force-included into every Eva, WP and Phase 0 parse). It can go once a release
carries the fix.
