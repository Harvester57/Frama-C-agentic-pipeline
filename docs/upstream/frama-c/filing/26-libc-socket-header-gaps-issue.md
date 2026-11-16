# [Libc] socket headers: `sockaddr_in` lacks `sin_zero` (and is smaller than `struct sockaddr`), `struct ip_mreq` is missing, `fd_set` not visible from `<sys/socket.h>`

<!-- Everything below this line is the issue description. -->

### Summary

Frama-C's socket headers differ from glibc in three ways that break correct programs: `struct sockaddr_in` has no `sin_zero` padding (so it is 8 bytes, smaller than `struct sockaddr`), `struct ip_mreq` is missing, and `fd_set` is not visible from `<sys/socket.h>`. Code written for glibc then fails to parse, or Eva reports a false alarm.

### Steps to reproduce the issue

Four small files, each accepted by gcc with glibc in its default mode.

`a.c`, a common idiom on correct code:

```c
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main(void)
{
  struct sockaddr_in sin;
  memset(&sin, 0, sizeof(struct sockaddr));
  sin.sin_family = AF_INET;
  return (int)sizeof sin;
}
```

`sinzero.c`:

```c
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

int bind_any(int fd, in_port_t port)
{
  struct sockaddr_in sin;
  memset(&sin, 0, sizeof(struct sockaddr));
  sin.sin_family = AF_INET;
  sin.sin_port = port;
  sin.sin_addr.s_addr = INADDR_ANY;
  memset(sin.sin_zero, 0, sizeof sin.sin_zero);
  return bind(fd, (struct sockaddr *)&sin, sizeof sin);
}
```

`mreq.c`:

```c
#include <sys/socket.h>
#include <netinet/in.h>

int join(int fd, struct in_addr group)
{
  struct ip_mreq mreq;
  mreq.imr_multiaddr = group;
  mreq.imr_interface.s_addr = INADDR_ANY;
  return setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof mreq);
}
```

`fdset.c`:

```c
#include <sys/socket.h>

int count(fd_set *s)
{
  return s != 0;
}
```

```
$ frama-c a.c -eva
$ frama-c sinzero.c
$ frama-c mreq.c
$ frama-c fdset.c
```

### Expected behaviour

All four parse, and Eva finds no alarm in `a.c`, as with glibc:
`struct sockaddr_in` has the `sin_zero[8]` padding and has the size of `struct sockaddr` (16 bytes),
`struct ip_mreq` (the argument of `IP_ADD_MEMBERSHIP`, which Frama-C's `<netinet/in.h>` defines)
exists, and `fd_set` is visible after `<sys/socket.h>`.

### Actual behaviour

```
[eva:alarm] a.c:8: Warning:
  function memset: precondition 'valid_s' got status invalid.
[kernel] sinzero.c:12: User Error:
  Cannot find field sin_zero in type struct sockaddr_in
[kernel] mreq.c:7: User Error:
  Cannot find field imr_multiaddr in type struct ip_mreq
[kernel] fdset.c:3: User Error:
  syntax error:
```

The first one is the most surprising: Eva reports an *invalid* precondition (a red alarm) on a
correct program, because Frama-C's `struct sockaddr_in` is 8 bytes while `struct sockaddr` is 16.

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at 3dff90fc70; also 34.0~beta (Selenium), same output
- Plug-in used: kernel, Eva (Frama-C libc)
- OS name: Debian GNU/Linux
- OS version: 13 (trixie)

### Additional information (optional)

On `3dff90fc70`:

- `share/libc/__fc_inet.h:39-43`: `struct sockaddr_in` has `sin_family`, `sin_port`, `sin_addr`
  only. POSIX does not require `sin_zero`, but glibc has it unconditionally, code uses it, and
  without it the structure is smaller than `struct sockaddr` (`__fc_define_sockaddr.h`:
  `sa_family` + `sa_data[14]`), so the usual `memset(&sin, 0, sizeof(struct sockaddr))` or
  `memcpy(&sin, sa, sizeof(struct sockaddr))` are out of bounds in Frama-C's model only.
- `share/libc/__fc_inet.h`: `IP_ADD_MEMBERSHIP` and `IP_DROP_MEMBERSHIP` are defined (lines 169-170,
  comment "ip_mreq"), as are `struct ip_mreqn` and `struct ipv6_mreq`, but `struct ip_mreq` and
  `struct ip_mreq_source` (for `IP_ADD_SOURCE_MEMBERSHIP` and friends, lines 171-174) are not.
  In glibc they are in the same `__USE_MISC` block as `ip_mreqn`.
- `fd_set` after `<sys/socket.h>` alone: glibc's `<sys/socket.h>` includes `<sys/types.h>`, which
  includes `<sys/select.h>` under `__USE_MISC` (the default `_DEFAULT_SOURCE` mode). This is not
  POSIX (with `gcc -std=c11`, glibc
  rejects `fdset.c` too), but Frama-C's `<sys/types.h>` already follows glibc's default mode for
  `u_char` and `caddr_t`, which glibc also guards with `__USE_MISC`.

A related observation: the `#if defined __USE_MISC || defined __USE_GNU` blocks of `__fc_inet.h`
(lines 176 and 227: `MCAST_*`, `struct ip_opts`, `struct ip_mreqn`, `struct in_pktinfo`) are never
enabled. No Frama-C libc header defines `__USE_MISC` or `__USE_GNU`, and `_GNU_SOURCE` or
`_DEFAULT_SOURCE` are not mapped to them, so `struct ip_mreqn x; x.imr_ifindex = 1;` fails even
with `#define _GNU_SOURCE`. I did not change that; you may want to either drop those guards, like
the other non-POSIX definitions of the libc, or map the feature macros as glibc's `features.h` does.

Proposed fix (merge request follows):

- `__fc_inet.h`: add `unsigned char sin_zero[8];` to `struct sockaddr_in`, and define
  `struct ip_mreq` and `struct ip_mreq_source` as glibc does, unguarded, next to `ipv6_mreq`.
- `sys/types.h`: include `<sys/select.h>` (non-POSIX, as glibc in its default mode).
- `sys/socket.h`: include `<sys/types.h>`, as glibc does.

With it, the four files parse and Eva reports no alarm on `a.c`. If you prefer to keep
`<sys/types.h>` and `<sys/socket.h>` POSIX-minimal, the `fd_set` part can be dropped
independently; the `sin_zero` and `ip_mreq` parts do not depend on it.

A merge request with a fix follows.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
