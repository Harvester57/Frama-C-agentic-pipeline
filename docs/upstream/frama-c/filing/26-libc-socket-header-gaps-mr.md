# [libc] add sockaddr_in.sin_zero, struct ip_mreq and fd_set via sys/types.h

- Source branch: `fix/libc-socket-glibc-compat` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `3dff90fc70`. Patch: [`../patches/26-libc-socket-header-gaps.patch`](../patches/26-libc-socket-header-gaps.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #2814.

## Problem

Three definitions that glibc provides in its default mode are missing from
Frama-C's libc, so code that builds with them does not parse:

- `struct sockaddr_in` has no `sin_zero[8]`, and is 8 bytes instead of
  `sizeof(struct sockaddr)` == 16: `memset(&sin, 0, sizeof(struct sockaddr))` gets an invalid
  `valid_s` precondition from Eva on correct code.
- `struct ip_mreq` (argument of `IP_ADD_MEMBERSHIP`, which is defined) and `struct ip_mreq_source`
  are not defined.
- `fd_set` is not visible after `#include <sys/socket.h>` alone (glibc: `<sys/socket.h>` includes
  `<sys/types.h>`, which includes `<sys/select.h>` in the default mode).

## Change

- `share/libc/__fc_inet.h`: `unsigned char sin_zero[8];` at the end of `struct sockaddr_in`;
  `struct ip_mreq` and `struct ip_mreq_source`, with glibc's fields, next to `struct ipv6_mreq`.
  They are not put in the `__USE_MISC || __USE_GNU` block with `ip_mreqn`, because nothing in
  Frama-C's libc defines those macros, so that block is never enabled (see the issue).
- `share/libc/sys/types.h`: `#include <sys/select.h>`, marked non-POSIX like the neighbouring
  `u_char` and `caddr_t`.
- `share/libc/sys/socket.h`: `#include <sys/types.h>`, as glibc does.

The last two make the `fd_set` part; they can be dropped from this MR independently if you prefer
to keep those headers POSIX-minimal. The `sin_zero` and `ip_mreq` parts do not depend on them.

Oracle changes, all expected:

- `tests/libc/oracle/socket.{0,1}.res.oracle`, `socket_h.0.res.oracle`, `sys_select.0.res.oracle`:
  `sizeof(struct sockaddr_in)` is now 16 (`addrlen ∈ {16}`, `socklen ∈ [0..16]`), `sin_zero`
  appears in the final states, and `__fc_fds_state` moves up in the sorted list of globals.
- `tests/libc/oracle/fc_libc.0.res.oracle`: `__fc_define_fd_set_t.h`, `__fc_define_timeval.h` and
  `__fc_select.h` leave the list of printed `#include`s (their declarations are now reached through
  `sys/select.h`, already listed).
- `plugins/e-acsl/tests/builtin/oracle/gen_{strcat,strcmp,strcpy,strlen}.0.c` and
  `plugins/e-acsl/tests/format/oracle/gen_{fprintf,printf}.0.c`: one added line,
  `#include "sys/select.h"`, in the list of headers of the generated code.

New test `tests/libc/socket_glibc_compat.c`: `fd_set` after `<sys/socket.h>`,
`sizeof(struct sockaddr_in) == sizeof(struct sockaddr)` (asserted, valid), the `memset` idiom (no
alarm), `sin_zero`, `ip_mreq`, `ip_mreq_source`.

## Testing

On a build of `3dff90fc70` with the patch (Debian 13, OCaml 5.5 switch, gcc 14.2):

- Reproducer from the issue: before, the Eva alarm and three `User Error`s; after, the four files
  parse and Eva reports no alarm. gcc accepts all four with glibc.
- ptests, default configuration: `dune build @tests/ptests_config` (all of `tests/`) and
  `@plugins/e-acsl/tests/ptests_config` (197 results): the only differences are the oracle changes
  above; after promoting them, `@tests/libc`, `@plugins/e-acsl/tests/builtin` and
  `@plugins/e-acsl/tests/format` pass.
- `@plugins/eva/tests/builtins/ptests_config` (its `linked_list.c` includes `stdio.c`, which reaches
  the changed headers through `__fc_libc.h`): passes unchanged. No other plugin test includes the
  changed headers directly or through another libc header.
- Cram: `dune build @tests/fc_script/runtest` passes.
- Not run: the default ptests of the other plugins (no test of theirs includes the changed
  headers), E-ACSL's `dev` configuration (compiles and runs the instrumented tests), and the mopsa
  cram tests.
- `git diff --check`: only the trailing spaces of the new `.res.oracle` (Frama-C output).
- `./dev/check-files.sh -p` (that is, `make check-lint` and `make check-headers` on the changed
  files) with ocp-indent 1.10.0 and clang-format 19.1.7: clean.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
