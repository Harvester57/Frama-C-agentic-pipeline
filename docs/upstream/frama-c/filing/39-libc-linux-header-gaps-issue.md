# [Libc] Add Linux `<sys/epoll.h>` and `<sys/inotify.h>` (and which other Linux gaps are wanted?)

<!-- Everything below this line is the issue description. -->

### Summary

Frama-C's libc has no `<sys/epoll.h>` and no `<sys/inotify.h>`, so a Linux program with an epoll
event loop or an inotify watcher does not parse at all. The libc already ships Linux-specific
headers with contracts (`sys/sendfile.h`, `sys/prctl.h`, `sys/random.h`, `sys/timex.h`), so I
would like to propose these two in the same style. A merge request follows.

I also list a few smaller Linux and glibc gaps found on the same targets, and ask which of them, if
any, you would want in the libc.

### Steps to reproduce the issue

`epoll.c`:

```c
#include <sys/epoll.h>
#include <unistd.h>

int main(void)
{
  int ep = epoll_create1(EPOLL_CLOEXEC);
  if (ep == -1)
    return 1;
  struct epoll_event ev;
  ev.events = EPOLLIN | EPOLLRDHUP | EPOLLET;
  ev.data.fd = 0;
  if (epoll_ctl(ep, EPOLL_CTL_ADD, 0, &ev) == -1) {
    close(ep);
    return 1;
  }
  struct epoll_event evs[8];
  int n = epoll_wait(ep, evs, 8, 1000);
  epoll_ctl(ep, EPOLL_CTL_DEL, 0, NULL);
  close(ep);
  return n < 0;
}
```

`inotify.c`:

```c
#include <sys/inotify.h>
#include <unistd.h>

int main(void)
{
  int fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
  if (fd == -1)
    return 1;
  int wd = inotify_add_watch(fd, "/etc/resolv.conf",
                             IN_MODIFY | IN_MOVE_SELF | IN_DELETE_SELF);
  if (wd != -1)
    inotify_rm_watch(fd, wd);
  close(fd);
  return (int)sizeof(struct inotify_event) != 16;
}
```

```
$ frama-c epoll.c -eva
$ frama-c inotify.c -eva
```

### Expected behaviour

Both files parse and Eva analyses them, as `sendfile` or `prctl` users do today. gcc with glibc
compiles both.

### Actual behaviour

```
[kernel] Parsing epoll.c (with preprocessing)
/tmp/w/epoll.c:1:10: fatal error: sys/epoll.h: No such file or directory
    1 | #include <sys/epoll.h>
      |          ^~~~~~~~~~~~~
compilation terminated.
[kernel] User Error: failed to run: gcc -E -C -I. [...] -nostdinc [...] '/tmp/w/epoll.c' [...]
[kernel] Frama-C aborted: invalid user input.
```

`inotify.c` gives the same with `sys/inotify.h`.

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at 95408044f7; also 34.0~beta (Selenium), same output
- Plug-in used: kernel, Eva (Frama-C libc)
- OS name: Debian GNU/Linux
- OS version: 13 (trixie)

### Additional information (optional)

Event-driven daemons and resolvers use these headers. On a resolver library, the whole library
could not be analysed with Eva or WP because one file includes them.

**Proposed headers** (the merge request), in the style of `sys/sendfile.h` and `sys/prctl.h`:

- `sys/epoll.h`:
  - the `EPOLL*`, `EPOLL_CTL_*` and `EPOLL_CLOEXEC` constants with the Linux values;
  - `epoll_data_t` and `struct epoll_event`, packed on x86_64 as in glibc and the kernel ABI (12
    bytes);
  - `epoll_create`, `epoll_create1`, `epoll_ctl`, `epoll_wait` and `epoll_pwait`.
- `sys/inotify.h`:
  - `struct inotify_event` and the `IN_*` constants;
  - `inotify_init`, `inotify_init1`, `inotify_add_watch` and `inotify_rm_watch`.
- The contracts are minimal:
  - descriptor ranges and buffer validity;
  - `assigns`/`\from`;
  - the `-1` error result;
  - for `epoll_wait`/`epoll_pwait`, the same `full`/`partial` behaviours as `read()`.
  - The kernel's interest and watch lists are `//missing:` comments.
- Sizes, offsets, constants and prototypes match glibc 2.41.

**Two points you may want to decide differently:**

- `struct epoll_event` is `__attribute__((__packed__))` under `#ifdef __x86_64__`, as in glibc.
  Code that takes `offsetof(struct epoll_event, data)` or `&ev.data` then gets the
  `kernel:typing:addr-of-packed-field` warning, which gcc does not give.
- As with `read()`, Eva still reports an initialization alarm when the caller reads `evs[i]` after
  a full `epoll_wait` (`n == maxevents`). The two behaviours are joined, and `read()` gives the same
  alarm on the same pattern.

**Other gaps found on the same targets.** The merge request does not change them; tell me which, if
any, you would accept. gcc with glibc (default mode) accepts each one:

| Missing | Frama-C | Note |
|---|---|---|
| `<netinet/ip_icmp.h>` (`struct icmphdr`, `ICMP_*`) | `fatal error` | `netinet/ip.h` is already there |
| `explicit_bzero` | `Calling undeclared function` | glibc 2.25 and the BSDs; one line in `string.h`, the contract of `bzero` |
| `pipe2`, `dup3`, `accept4` | `Calling undeclared function` | all three are in POSIX.1-2024 |
| `<sys/eventfd.h>`, `<sys/timerfd.h>`, `<sys/signalfd.h>` | `fatal error` | same family as epoll |
| `_IO`, `_IOR`, `_IOW`, `_IOWR` in `<sys/ioctl.h>` | `syntax error` | Linux request encoding, per-architecture |
| `syscall()` and `<sys/syscall.h>` | `Calling undeclared function`, `fatal error` | `SYS_*` is per-architecture; I would understand a no |

I do not ask for glibc's internal names (`__int8_t`, `__flexarr`, `__attr_access`, ...) or for the
kernel UAPI headers (`<elf.h>`, `<linux/*.h>`).

A merge request with the two headers follows.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
