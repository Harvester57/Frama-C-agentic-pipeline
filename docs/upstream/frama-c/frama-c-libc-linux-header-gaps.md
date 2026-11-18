# Libc: no `<sys/epoll.h>` or `<sys/inotify.h>`, and a few smaller Linux/glibc gaps

Draft feature request for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues),
with a merge request. Filed on 2026-11-18 as [#2828](https://git.frama-c.com/pub/frama-c/-/work_items/2828), with merge request [!56](https://git.frama-c.com/pub/frama-c/-/merge_requests/56). Issue 39 of this folder.

**Filing package:** [issue](./filing/39-libc-linux-header-gaps-issue.md), [MR](./filing/39-libc-linux-header-gaps-mr.md), [reproducer](./repro/39-libc-linux-header-gaps.sh), [patch](./patches/39-libc-linux-header-gaps.patch)

## Summary

Frama-C's libc has no `<sys/epoll.h>` and no `<sys/inotify.h>`. Any Linux program with an epoll
event loop or an inotify watcher stops at the include with `fatal error: sys/epoll.h: No such file
or directory`. Event-driven daemons and resolvers are built this way. The c-ares run (see below)
lost Eva and WP on the whole library to this.

This is a feature request, not a bug. The libc models POSIX first, and neither header is POSIX.
But it already ships Linux-only headers with contracts (`sys/sendfile.h`, `sys/prctl.h`,
`sys/random.h`, `sys/timex.h`), so a header in that style is within the libc's current scope. The
patch adds both headers that way.

The inventory found other gaps. They are listed in the issue as questions for the maintainers, and
the patch does not touch them (see [Inventory](#inventory)).

Found on c-ares `run-1`, 2026-11-16 (`build/lib/libcares.a` and `libcares.so` went to the GCC
fallback). See the epoll/inotify entry of
[`../../troubleshooting/kernel-and-stubs.md`](../../troubleshooting/kernel-and-stubs.md) and
[`../../runs/2026-11-16-c-ares-run1-supervision.md`](../../runs/2026-11-16-c-ares-run1-supervision.md).
The errors in that entry (`__flexarr`, `__attr_access`, `__sigset_t`, `timespec`) come from the
pipeline's `-idirafter /usr/include/x86_64-linux-gnu`, which lets glibc's own header be found. Stock
Frama-C stops earlier, at the missing file.

## Versions

| | Result |
|---|---|
| `35.0~~dev (Bromine)`, `master` at `95408044f7` (image `framac-master-audit:9540804`) | **both headers missing** (2 of 2 reproducer checks fail) |
| `34.0~beta (Selenium)` (image `framac-analysis:latest`) | **both missing**, identical output |
| `master` + patch (commit `732f33be36`, built and installed in a container from the master image) | `RESULT: fixed` |

## Inventory

Each line is one small file, parsed by Frama-C with its own libc and compiled by gcc 14 with glibc in
the default mode (`gnu17`). gcc accepts every file. These are the `-others.c` lines of the
reproducer.

| Missing on master | Frama-C error | Sorting |
|---|---|---|
| `<sys/epoll.h>` | `fatal error: sys/epoll.h` | **requested, patched** |
| `<sys/inotify.h>` | `fatal error: sys/inotify.h` | **requested, patched** |
| `<netinet/ip_icmp.h>` (`struct icmphdr`, `ICMP_*`) | `fatal error` | asked in the issue: Linux/BSD, used by ping-like code; `netinet/ip.h` is already there |
| `syscall()` and `<sys/syscall.h>` (`SYS_*`) | `Calling undeclared function syscall`, `fatal error` | asked: `syscall()` is easy to declare, but `SYS_*` is per-architecture and has no useful contract; probably not wanted |
| `explicit_bzero` (glibc 2.25, the BSDs; C23's equivalent is `memset_explicit`) | `Calling undeclared function` | asked: one declaration in `string.h`, contract of `bzero` |
| `_IO`, `_IOR`, `_IOW`, `_IOWR` in `<sys/ioctl.h>` | `syntax error` | asked: Linux request-encoding macros, arch-dependent |
| `<sys/eventfd.h>`, `<sys/timerfd.h>`, `<sys/signalfd.h>` | `fatal error` | asked, lower priority: same family as epoll, not seen on the pipeline's targets |
| `pipe2`, `dup3`, `accept4` | `Calling undeclared function` | asked: all three are in POSIX.1-2024 |

Not requested, since upstream will not want them:

- glibc internals that only matter when glibc's own headers are mixed in: `__int8_t`, `__uint32_t`
  and friends, `__attr_access`, `__flexarr`, and the guard collisions (`__sigset_t_defined`,
  `_STRUCT_TIMESPEC` against `__FC_DEFINE_TIMESPEC_H`). Issue #146 shows that the maintainers
  removed unannotated "dummy" headers rather than mirror glibc.
- Linux UAPI headers (`<elf.h>`, `<linux/*.h>`, `<asm/*.h>`), which belong to the kernel.
- `memset_s` (C11 Annex K): glibc lacks it too, so gcc rejects the file as well.

Already present on master, though the pipeline's notes suggested otherwise: `getrandom`,
`reallocarray`, `memrchr`, `struct ip`, `clock_gettime`, `<sys/utsname.h>`, `<sys/vfs.h>`,
`<sys/wait.h>`, `u_short`. MR !45 (#2814) covers `sin_zero`, `ip_mreq`, `ip_mreq_source` and
`fd_set` through `<sys/types.h>`, and this package does not overlap with it.

`pipe2`, `dup3` and `accept4` are the POSIX.1-2024 additions. Their absence is a libc conformance
gap rather than a Linux one, so they could be a separate issue. The issue mentions them only.

## Reproduction

[`./repro/39-libc-linux-header-gaps.sh`](./repro/39-libc-linux-header-gaps.sh) runs Eva on
[`./repro/39-libc-linux-header-gaps-epoll.c`](./repro/39-libc-linux-header-gaps-epoll.c) (an epoll
event loop) and
[`./repro/39-libc-linux-header-gaps-inotify.c`](./repro/39-libc-linux-header-gaps-inotify.c) (an
inotify watcher). It then prints the inventory from
[`./repro/39-libc-linux-header-gaps-others.c`](./repro/39-libc-linux-header-gaps-others.c), one
`-DGAP_*` at a time; only the first two checks decide `RESULT`. On master:

```
--- 39-libc-linux-header-gaps-epoll.c (Eva)
fatal error: sys/epoll.h
--- 39-libc-linux-header-gaps-inotify.c (Eva)
fatal error: sys/inotify.h
--- other gaps (informational)
ip_icmp: frama-c fatal error: netinet/ip_icmp.h; gcc ok
sys_syscall: frama-c fatal error: sys/syscall.h; gcc ok
syscall: frama-c Calling undeclared function syscall; gcc ok
explicit_bzero: frama-c Calling undeclared function explicit_bzero; gcc ok
ioctl_iowr: frama-c syntax error; gcc ok
eventfd: frama-c fatal error: sys/eventfd.h; gcc ok
timerfd: frama-c fatal error: sys/timerfd.h; gcc ok
signalfd: frama-c fatal error: sys/signalfd.h; gcc ok
pipe2: frama-c Calling undeclared function pipe2; gcc ok
dup3: frama-c Calling undeclared function dup3; gcc ok
accept4: frama-c Calling undeclared function accept4; gcc ok
RESULT: bug present (2 of 2 checks fail)
```

With the patch, both Eva checks print `ok`, Eva reports no alarm on either file, and the result is
`RESULT: fixed`. The eleven informational lines do not change.

## Fix

[`./patches/39-libc-linux-header-gaps.patch`](./patches/39-libc-linux-header-gaps.patch) is one
commit on `feature/libc-epoll-inotify` from `95408044f7`, "[libc] add Linux headers sys/epoll.h and
sys/inotify.h". It follows `sys/sendfile.h` and `sys/prctl.h` (licence header, `// Non-POSIX;
Linux-specific`, `__PUSH_FC_STDLIB`, `__BEGIN_DECLS`).

**`share/libc/sys/epoll.h`**

- Every `EPOLL*` event bit, `EPOLL_CTL_ADD/DEL/MOD` and `EPOLL_CLOEXEC`, with the Linux values.
- The `epoll_data` union and `struct epoll_event`. The struct is packed under `__x86_64__`, as
  glibc does (12 bytes on x86_64).
- `epoll_create`, `epoll_create1`, `epoll_ctl`, `epoll_wait` and `epoll_pwait`.
- The contracts cover:
  - descriptor ranges (`__FC_MAX_OPEN_FILES`);
  - `valid_read(event)` unless the op is `EPOLL_CTL_DEL`;
  - `\valid(events + (0 .. maxevents - 1))`;
  - a null or readable `sigmask`;
  - `assigns`/`\from`;
  - for `epoll_wait` and `epoll_pwait`, the `full` / `partial_timeout_or_error` behaviours of
    `read()` (on `Frama_C_entropy_source`), which state which events are initialized.
- The kernel's interest list is a `//missing:` comment.

**`share/libc/sys/inotify.h`**

- `struct inotify_event` with a flexible `name[]` member.
- Every `IN_*` constant, including `IN_CLOEXEC` and `IN_NONBLOCK` (the `O_*` values of
  `fcntl.h`).
- `inotify_init`, `inotify_init1`, `inotify_add_watch` (`valid_read_string(pathname)`) and
  `inotify_rm_watch`.
- The watch list is a `//missing:` comment.

**Other files**

- Both headers are added to `share/libc/__fc_libc.h` and `tests/libc/fc_libc.c`, which
  `tests/libc/check_full_libc.sh` requires.
- New Eva tests `tests/libc/sys_epoll_h.c` and `sys_inotify_h.c`, with their oracles. Every
  precondition and every assertion is valid, with no alarm.
- `tests/libc/oracle/fc_libc.0.res.oracle` and `fc_libc.2.res.oracle` each gain two lines, the new
  `#include` and `Parsing` lines.

**ABI check**

A scratch file of `_Static_assert`s compares the patched headers with glibc 2.41's:

- `sizeof(struct epoll_event) == 12` and `offsetof(..., data) == 4`;
- `sizeof(epoll_data_t) == 8`;
- `sizeof(struct inotify_event) == 16` and `offsetof(..., name) == 16`;
- every constant;
- function-pointer assignments that check the nine prototypes.

It passes with gcc against glibc and with Frama-C against the patched libc. The file is not part of
the patch.

**Design notes for the maintainers**

- **`__attribute__((__packed__))` under `#ifdef __x86_64__`.** This matches glibc's
  `__EPOLL_PACKED` and the kernel ABI. Frama-C warns `kernel:typing:addr-of-packed-field` only when
  code takes `offsetof` or the address of `data`, which gcc accepts silently. That is why the new
  test checks `sizeof` and not `offsetof`.
- **Initialization after `epoll_wait`.** Eva still reports an initialization alarm when reading
  `evs[i]` after a full `epoll_wait` (`n == maxevents`), because the two behaviours are joined.
  Upstream's own `read()` gives the same alarm on the same pattern (checked on master with a
  `read()` version of the loop). So the test does not read the events, and the issue mentions it.

## Validation

`master` `95408044f7` with the patch, built and installed in the container
`upstream-libc-wp` (image `framac-master-audit:9540804`).

| Check | `master` | Patched |
|---|---|---|
| Reproducer (Eva on `-epoll.c`, `-inotify.c`) | `fatal error` x2, `RESULT: bug present` | `ok` x2, `RESULT: fixed` |
| New tests `sys_epoll_h.c`, `sys_inotify_h.c` (ptests, patch commit's tests on `95408044f7`) | `fatal error: sys/epoll.h: No such file or directory`, same for `sys/inotify.h` | pass |
| `dune build @tests/libc/ptests_config` | — | only `fc_libc.0` and `fc_libc.2` move (two lines each) plus the two new oracles; passes after promotion (rc 0, empty output) |
| `tests/libc/check_full_libc.sh ../../share/libc` | — | rc 0 |
| `git grep` of every oracle for libc header lists | — | only the two `fc_libc` oracles list headers |
| `@tests/ptests_config` (1149 results), `@plugins/eva/tests/builtins/ptests_config` (62), `@plugins/e-acsl/tests/ptests_config` (197, default configuration), one `dune build -j 6` | — | rc 0, no difference, in 1 min 20 s. Unchanged results may come from dune's cache |
| Other plugins' default ptests, E-ACSL `dev`, cram | — | not run |
| `./dev/check-files.sh -p HEAD~1` | — | `Lint 10 file(s)`, rc 0 |

`ulimit -c 1` was not applied before the ptests: the container's hard core limit is already 0, so
the call fails with `Operation not permitted`.

## Workaround

On the pipeline side, `templates/fc_stubs/sys/epoll.h` and `sys/inotify.h` were parse shims around
glibc's header (commit `20a23bd`). Since 2026-11-18 they are the two headers of this
patch for Eva and WP, with their contracts; E-ACSL still reads glibc's header. From `__BEGIN_DECLS`
to `__END_DECLS` the pipeline's text is the patch's, and
`tests/test_fc_stub_repairs.py::test_linux_event_headers_carry_the_text_of_the_upstream_patch`
compares the two: a change the maintainers ask for in !56 goes into the patch file and into the
pipeline's headers together. Once a release ships the headers, Frama-C's own libc directory comes
first on the include path and the pipeline's two files are no longer read.

## Candidate change for !56 (found 2026-11-18, not sent)

The pipeline's copy of `sys/epoll.h` has one clause the patch lacks, on `epoll_wait` and
`epoll_pwait`:

```
ensures result_bounded: -1 <= \result <= maxevents;
```

- **Why:** the patch states the result only inside the `full` and `partial_timeout_or_error`
  behaviours, whose `assumes` read the volatile `Frama_C_entropy_source`. WP gives each read of a
  volatile its own value, so it assumes neither behaviour and knows nothing about the result. A
  caller cannot prove `n <= maxevents`, which the index of `events[i]` in an event loop needs:
  `[wp] [Timeout] typed_poll8_ensures` on `34.0~beta`. With the clause WP proves the wrapper and an
  event loop.
- **Upstream's `read()` has the same weakness** (`[Timeout] typed_read8_ensures` on the same image;
  proved with `-wp-no-volatile`), so this is the libc's contract style and the maintainers may
  prefer to keep the two alike. Not checked on `master`.
- **The patch's own tests did not show it:** they are Eva tests, and they do not read the events.
- **Not sent:** the clause is not in the patch file, in the merge request or in a comment. Filing
  is paused (see the README of this folder), and a push to the branch of !56 needs the owner's
  go-ahead.

## Tracker

Live search on 2026-11-17 (glab api, read-only) for `epoll`, `inotify`, `ip_icmp` and
`explicit_bzero`: no hit. The 2026-11-09 export
([`./pub-frama-c_work_items_2026-11-09.csv`](./pub-frama-c_work_items_2026-11-09.csv)) has none
either. Context:

- #146 (closed): unannotated dummy headers were removed from the libc. This is why the patch ships
  contracts and a test rather than bare declarations.
- !5 (closed): an earlier `sys/sendfile.h` MR.
- !45 / #2814: the socket gaps, which this package does not overlap.
