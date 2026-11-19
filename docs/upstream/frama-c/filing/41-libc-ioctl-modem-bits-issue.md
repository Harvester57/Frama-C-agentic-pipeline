# [Libc] `<sys/ioctl.h>` defines `TIOCMGET` and `TIOCMSET` but not the `TIOCM_*` modem line bits

<!-- Everything below this line is the issue description. -->

### Summary

Frama-C's `<sys/ioctl.h>` defines the modem-control requests `TIOCMGET`, `TIOCMBIS`, `TIOCMBIC`,
`TIOCMSET` and `TIOCMIWAIT`, but none of the `TIOCM_*` bits that these requests read and write.
Serial-port code that sets RTS or DTR, or tests CTS or the carrier, does not parse.

### Steps to reproduce the issue

`rts.c`:

```c
#include <sys/ioctl.h>

int set_rts(int fd, int on)
{
  int lines = 0;
  if (ioctl(fd, TIOCMGET, &lines) == -1)
    return -1;
  if (on)
    lines |= TIOCM_RTS;
  else
    lines &= ~TIOCM_RTS;
  return ioctl(fd, TIOCMSET, &lines);
}
```

```
$ frama-c rts.c
```

### Expected behaviour

The file parses. gcc with glibc compiles it, also with `-std=c11 -pedantic`.

### Actual behaviour

```
[kernel] Parsing rts.c (with preprocessing)
[kernel] rts.c:9: User Error: 
  Cannot resolve variable TIOCM_RTS
  7         return -1;
  8       if (on)
  9         lines |= TIOCM_RTS;
                     ^^^^^^^^^
  10      else
  11        lines &= ~TIOCM_RTS;
[kernel] Frama-C aborted: invalid user input.
```

The same happens for each of the eleven names: `TIOCM_LE`, `TIOCM_DTR`, `TIOCM_RTS`, `TIOCM_ST`,
`TIOCM_SR`, `TIOCM_CTS`, `TIOCM_CAR`, `TIOCM_RNG`, `TIOCM_DSR`, `TIOCM_CD` and `TIOCM_RI`.

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at b80fcac74f; also 34.0~beta (Selenium), same output
- Plug-in used: kernel (Frama-C libc)
- OS name: Debian GNU/Linux
- OS version: 13 (trixie)

### Additional information (optional)

I found this on libmodbus: its RTU backend (`src/modbus-rtu.c`) sets and clears RTS with
`TIOCMGET` and `TIOCMSET`, and Frama-C stops at that line.

- **What glibc provides.** In glibc 2.41, `<sys/ioctl.h>` includes `<bits/ioctl-types.h>`, which
  defines these eleven names without any feature-test guard. Their values are those of Linux
  `<asm-generic/termios.h>`.
- **Where they would go.** `share/libc/sys/ioctl.h` already has the requests (`TIOCMGET` at
  `0x5415` to `TIOCMSET` at `0x5418`, and `TIOCMIWAIT`) and the bits of other requests
  (`TIOCPKT_*`, `TIOCSER_TEMT`). The eleven definitions fit next to those. `ioctl` keeps its
  contract: only macros are added.
- **Left out.** Linux `<asm-generic/termios.h>` also defines `TIOCM_OUT1`, `TIOCM_OUT2` and
  `TIOCM_LOOP`. glibc's `<sys/ioctl.h>` does not expose them (gcc rejects `TIOCM_LOOP` after
  `<sys/ioctl.h>` and `<termios.h>`), so I did not add them. Tell me if you want them too.
- **Related.** #2828 asks which Linux gaps you want in the libc, and lists the `_IO`, `_IOR`,
  `_IOW` and `_IOWR` macros of this same header. I report this one separately because it needs
  no decision of that kind: the header already has the requests, and the bits are plain constants.

A merge request with the eleven definitions and a test follows.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
