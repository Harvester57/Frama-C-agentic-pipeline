# Frama-C libc: `getsockopt` precondition uses an unbounded range (unsatisfiable for Eva, rejected by WP)

Draft bug report for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).

## Summary

In `share/libc/sys/socket.h`, behavior `other_options` of `getsockopt` requires

```c
requires optval_null_or_valid:
  optval == \null || \valid(((char*)optval)+(0..));
```

The range `(0..)` has no upper bound, so the precondition requires an infinitely large
valid block, which no object satisfies. Every call with a non-null `optval`, other than
`SOL_SOCKET`/`SO_ERROR`, is therefore rejected:

- **Eva** reports the precondition as **Invalid** on correct calls, considers the call
  non-terminating, and analyses nothing after it in the caller (the rest of the function
  becomes dead code, so alarms there are silently missed).
- **WP** aborts: `User Error: Invalid infinite range (global L_opt_402)+(0..)`, so no
  function calling `getsockopt` can be proved at all.

The sibling `setsockopt` already bounds its buffer correctly:
`\valid_read(((char *)optval)+(0..optlen-1))`.

## Versions

- Reproduced with Frama-C `34.0~~dev (Selenium)`.
- The same text is in the public GitHub snapshot up to 20.0 (Calcium, 2019), so the
  issue is at least five years old. I could not read the current GitLab master.

## Reproduction

`caller.c`:

```c
#include <sys/socket.h>
#ifndef OPTLEN
#define OPTLEN sizeof(int)
#endif
/*@ requires 0 <= fd < __FC_MAX_OPEN_SOCKETS; */
int get_opt(int fd) {
  int opt;
  socklen_t olen = OPTLEN;
  return getsockopt(fd, 270 /* SOL_NETLINK */, 1, &opt, &olen);
}
int main(void) { return get_opt(3); }
```

```text
$ frama-c caller.c -eva
[eva:alarm] caller.c:9: Warning:
  function getsockopt, behavior other_options: precondition 'optval_null_or_valid' got status invalid.

$ frama-c caller.c -wp -wp-fct get_opt -wp-model Bytes
[wp] FRAMAC_SHARE/libc/sys/socket.h:398: User Error:
  Invalid infinite range (global L_opt_402)+(0..)
[kernel] Plug-in wp aborted: invalid user input.
```

The call is correct: `optval` points to a 4-byte object and `*optlen == 4`, and
getsockopt(2) writes at most `*optlen` bytes (POSIX: a longer value "shall be silently
truncated"). Any level/option other than `SOL_SOCKET`/`SO_ERROR` triggers it
(`SO_RCVBUF`, `TCP_INFO`, `SO_PEERCRED`, `SOL_NETLINK` options, ...).

## Proposed fix

Bound the buffer by `*optlen`, as `setsockopt` does with `optlen`. Bounding the two
`assigns` ranges as well keeps the analysis precise. Nothing else changes; the
`so_error` behavior is untouched.

```diff
--- a/share/libc/sys/socket.h
+++ b/share/libc/sys/socket.h
@@ getsockopt @@
   requires valid_sockfd: 0 <= sockfd < __FC_MAX_OPEN_SOCKETS;
   requires valid_optlen: \valid(optlen);
-  assigns ((char*)optval)[0..], \result
+  assigns ((char*)optval)[0..*optlen-1], \result
           \from indirect:sockfd, indirect:level, indirect:optname,
@@
   behavior other_options:
     assumes optname_not_error: !(level == SOL_SOCKET && optname == SO_ERROR);
     requires optval_null_or_valid:
-      optval == \null || \valid(((char*)optval)+(0..));
-    assigns ((char*)optval)[0..], \result
+      optval == \null || \valid(((char*)optval)+(0..*optlen-1));
+    assigns ((char*)optval)[0..*optlen-1], \result
             \from indirect:sockfd, indirect:level, indirect:optname,
```

`*optlen == 0` gives an empty range (valid), and a null `optval` stays allowed, as before.

## Validation of the proposed contract

Tested by declaring the patched contract in place of the stock one (same file and
program as above; `-DOPTLEN=8` makes the caller claim 8 bytes for a 4-byte `int`).

| Program | Stock libc | Patched |
|---|---|---|
| Eva, correct call | precondition Invalid | 7/7 preconditions valid |
| Eva, `*optlen` (8) larger than `optval` (4 bytes) | Invalid | Invalid (`optval_null_or_valid`), as it should be |
| Eva, `optval == NULL` | valid | valid |
| Eva, `SOL_SOCKET`/`SO_ERROR`, correct | valid | valid (behavior unchanged) |
| Eva, `SO_ERROR` with `*optlen == 8` | — | Invalid (`optlen_value`), unchanged |
| WP (`-wp-model Bytes`), correct call | aborts: invalid infinite range | 8/8 goals proved |
| WP (`Bytes`), `*optlen` 8 > buffer | aborts | `optval_null_or_valid` not proved (expected) |
| WP (`Bytes`), `SO_ERROR` | aborts | 8/8 goals proved |

With the default Typed model, the patched precondition times out on the correct call,
because of the `int *` to `char *` cast (a known Typed limitation), not the contract.

## Other occurrences

A scan of every ACSL contract under `share/libc` for ranges without an upper bound found
this `requires` clause as the **only** one. All other open ranges (`s[0..]` in `stdio.h`,
`argz.h`, `pwd.h`, `sys/stat.h`, `sys/uio.h`, `recvmsg`, ...) are in `assigns`/`\from`
clauses, where an over-approximation is sound and analysers accept it.

(The `assigns` range of `getsockopt` itself is one of those; the patch bounds it only for
precision.)
