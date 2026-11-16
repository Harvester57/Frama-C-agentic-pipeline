# Libc: socket headers lack `sockaddr_in.sin_zero` (so `sockaddr_in` is smaller than `sockaddr`), `struct ip_mreq`, and `fd_set` through `<sys/socket.h>`

**Filed upstream on 2026-11-15:** issue [#2814](https://git.frama-c.com/pub/frama-c/-/work_items/2814), merge request [!45](https://git.frama-c.com/pub/frama-c/-/merge_requests/45).

Draft bug report for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues). Not
filed yet. Issue 26 of this folder.

**Filing package:** [issue](./filing/26-libc-socket-header-gaps-issue.md), [MR](./filing/26-libc-socket-header-gaps-mr.md), [reproducer](./repro/26-libc-socket-header-gaps.sh), [patch](./patches/26-libc-socket-header-gaps.patch)

## Summary

Three gaps of Frama-C's libc against glibc in its default mode (only glibc's headers were checked;
musl and the BSDs were not):

1. `struct sockaddr_in` has no `sin_zero[8]`. Code that touches it does not parse
   (`Cannot find field sin_zero in type struct sockaddr_in`), and the structure is 8 bytes instead
   of `sizeof(struct sockaddr)` == 16. So `memset(&sin, 0, sizeof(struct sockaddr))`, a common
   idiom on correct code, gets a **red** `valid_s` precondition from Eva.
2. `struct ip_mreq` (and `struct ip_mreq_source`) are missing, although `IP_ADD_MEMBERSHIP` and the
   `*_SOURCE_MEMBERSHIP` macros are defined.
3. `fd_set` is not visible after `#include <sys/socket.h>` alone (`syntax error` at `fd_set *`).

Found on ptf-original run-1, unit `src/LibPtfCom/libPtfCom.a` (`LitePing.c:111`,
`LowLevelPortHandler.c:126` and `:237`), 2026-11-10: the whole unit fell back to GCC (see the
`fd_set` entry of
[`../../troubleshooting/kernel-and-stubs.md`](../../troubleshooting/kernel-and-stubs.md)).

### Bug or compatibility gap

None of the three is required by POSIX. They are glibc behaviour that Frama-C's libc otherwise
follows:

- `sin_zero` is unconditional in glibc (`gcc -std=c11` still has it). The size mismatch with `struct sockaddr` makes correct code fail in Frama-C's model only,
  which is the strongest reason to fix it.
- `struct ip_mreq` is in glibc's `__USE_MISC` block, together with `ip_mreqn` and
  `ip_mreq_source`. Frama-C has `ip_mreqn` but not the other two.
- `fd_set`: glibc's `<sys/socket.h>` includes `<sys/types.h>`, which includes `<sys/select.h>` under
  `__USE_MISC` (the default `_DEFAULT_SOURCE` mode). With `gcc -std=c11`, glibc rejects the `fd_set`
  file too. Frama-C's `<sys/types.h>` already exposes other `__USE_MISC` definitions (`u_char`,
  `caddr_t`) unconditionally.

A related finding, not changed by the patch: the `#if defined __USE_MISC || defined __USE_GNU`
blocks of `__fc_inet.h` (lines 176 and 227 on `3dff90fc70`: `MCAST_*`, `struct ip_opts`,
`struct ip_mreqn`, `struct in_pktinfo`) are dead by default. No Frama-C libc header defines those
macros, and `_GNU_SOURCE` / `_DEFAULT_SOURCE` are not mapped to them: with `#define _GNU_SOURCE`,
`struct ip_mreqn x; x.imr_ifindex = 1;` fails with `Cannot find field imr_ifindex in type struct
ip_mreqn` (checked on the master image), while gcc accepts it. The issue asks the maintainers which
way they want it.

## Versions

| | Result |
|---|---|
| `35.0~~dev (Bromine)`, `master` at `3dff90fc70` (image `framac-master-audit:3dff90f`) | **all three gaps present** (4 of 4 reproducer checks fail) |
| `34.0~beta (Selenium)`, opam build (image `framac-analysis:fc34`) | **all three present**, identical output |

The recent libc merges on master did not touch these definitions.

## Reproduction

[`./repro/26-libc-socket-header-gaps.sh`](./repro/26-libc-socket-header-gaps.sh) runs Eva on
[`./repro/26-libc-socket-header-gaps.c`](./repro/26-libc-socket-header-gaps.c) (the `memset`
idiom) and parses
[`./repro/26-libc-socket-header-gaps-sinzero.c`](./repro/26-libc-socket-header-gaps-sinzero.c),
[`./repro/26-libc-socket-header-gaps-mreq.c`](./repro/26-libc-socket-header-gaps-mreq.c) and
[`./repro/26-libc-socket-header-gaps-fdset.c`](./repro/26-libc-socket-header-gaps-fdset.c). On
master:

```
--- 26-libc-socket-header-gaps.c (Eva)
[eva:alarm] 26-libc-socket-header-gaps.c:11: Warning: 
  function memset: precondition 'valid_s' got status invalid.
--- 26-libc-socket-header-gaps-sinzero.c
[kernel] 26-libc-socket-header-gaps-sinzero.c:14: User Error: 
  Cannot find field sin_zero in type struct sockaddr_in
--- 26-libc-socket-header-gaps-mreq.c
[kernel] 26-libc-socket-header-gaps-mreq.c:8: User Error: 
  Cannot find field imr_multiaddr in type struct ip_mreq
--- 26-libc-socket-header-gaps-fdset.c
[kernel] 26-libc-socket-header-gaps-fdset.c:5: User Error: 
  syntax error:
RESULT: bug present (4 of 4 checks fail)
```

gcc (glibc, default `gnu17`) accepts all four files.

## Fix

[`./patches/26-libc-socket-header-gaps.patch`](./patches/26-libc-socket-header-gaps.patch), one
commit on `fix/libc-socket-glibc-compat` from `3dff90fc70`, "[libc] add sockaddr_in.sin_zero,
struct ip_mreq and fd_set via sys/types.h":

- `share/libc/__fc_inet.h`: `unsigned char sin_zero[8];` in `struct sockaddr_in`;
  `struct ip_mreq` and `struct ip_mreq_source` with glibc's fields, unguarded, next to
  `struct ipv6_mreq`.
- `share/libc/sys/types.h`: `#include <sys/select.h>` (non-POSIX, like `u_char`, `caddr_t`).
- `share/libc/sys/socket.h`: `#include <sys/types.h>`, as glibc.
- New test `tests/libc/socket_glibc_compat.c`. Oracle updates: `tests/libc` `socket.{0,1}`,
  `socket_h.0`, `sys_select.0` (`sockaddr_in` is 16 bytes), `fc_libc.0` (three internal headers
  leave the `#include` list), and six E-ACSL `gen_*.c` oracles in `builtin/` and `format/` (one
  added `#include "sys/select.h"` line each).

The `fd_set` part (the last two header changes and the E-ACSL oracle lines) can be dropped
independently if the maintainers want `<sys/types.h>` and `<sys/socket.h>` to stay
POSIX-minimal; the MR says so.

Output with the fix: every check prints `ok`, `RESULT: fixed`.

## Validation

Patched `3dff90fc70`, built and installed over the switch of a throwaway copy of
`framac-master-audit:3dff90f`.

| Check | `master` | Patched |
|---|---|---|
| `memset(&sin, 0, sizeof(struct sockaddr))`, Eva | invalid `valid_s` | no alarm |
| `sin.sin_zero` | `Cannot find field` | parses |
| `struct ip_mreq` | `Cannot find field` (incomplete type) | parses |
| `fd_set` after `<sys/socket.h>` alone | `syntax error` | parses |
| ptests `@tests/ptests_config` | — | only the libc oracle changes listed above, then `@tests/libc` passes after promotion |
| ptests `@plugins/e-acsl/tests/ptests_config` (197 results) | — | only the six `gen_*.c` lines; `builtin` and `format` pass after promotion |
| ptests `@plugins/eva/tests/builtins/ptests_config` (`linked_list.c` includes `stdio.c`) | — | pass, unchanged |
| Cram `@tests/fc_script/runtest` | — | pass |
| Other plugins' ptests | — | not run: a grep of every plugin test tree for the changed headers and the libc files that include them (`__fc_libc.h`, `stdio.c`, `netdb.h`, `net/if.h`, `netinet/tcp.h`, `resolv.h`, `__fc_runtime.c`) hits only E-ACSL and Eva `builtins` |
| E-ACSL `dev` configuration, mopsa cram tests | — | not run |
| `make check-lint`, `make check-headers` | — | not run (tools not installed) |

## Workaround

The pipeline repairs `fd_set` and `struct ip_mreq` in
[`../../../templates/fc_stubs/fc_compat_types.h`](../../../templates/fc_stubs/fc_compat_types.h)
(force-included, `__fc_libc` branch only), and the analysis image patches the installed
`__fc_inet.h` in place with a `RUN` step of the `Dockerfile` that appends `sin_zero[8]` to
`struct sockaddr_in` (a force-included redefinition would collide with `__fc_inet.h`). Both go away
once the patch is in a release.

## Tracker

Not filed at the time of writing (see the filing note at the top). Nothing matches in the 2026-11-09 export
([`./pub-frama-c_work_items_2026-11-09.csv`](./pub-frama-c_work_items_2026-11-09.csv)), and a live
search on 2026-11-15 found nothing either.
