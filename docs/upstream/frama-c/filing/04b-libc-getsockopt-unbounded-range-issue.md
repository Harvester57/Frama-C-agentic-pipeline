# [Libc] `getsockopt` precondition `\valid(((char*)optval)+(0..))` is unsatisfiable: Eva rejects correct calls, WP aborts

<!-- Everything below this line is the issue description. -->

### Summary

The libc contract of `getsockopt` requires `\valid(((char*)optval)+(0..))`, an unbounded range that no buffer satisfies. Eva reports correct calls as alarms and the call as non-terminating, and WP stops with "Invalid infinite range". Bounding the range by `*optlen` fixes both.

### Steps to reproduce the issue

`g.c`:

```c
#include <sys/socket.h>

#ifndef OPTLEN
#define OPTLEN sizeof(int)
#endif

/*@ requires 0 <= fd < __FC_MAX_OPEN_SOCKETS; */
int get_rcvbuf(int fd) {
  int opt = 0;
  socklen_t olen = OPTLEN;
  int r = getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &opt, &olen);
  return r < 0 ? -1 : opt;
}

int main(void) { return get_rcvbuf(3); }
```

```sh
frama-c g.c -eva -then -report | grep "optval_null_or_valid'' at"
frama-c g.c -eva | grep -A1 'Values at end of function get_rcvbuf'
frama-c g.c -wp -wp-fct get_rcvbuf -wp-model Bytes
```

### Expected behaviour

The call is correct: `optval` points to a 4-byte object and `*optlen == 4`. getsockopt(2) writes
at most `*optlen` bytes into `optval` (POSIX: a longer value "shall be silently truncated"). Eva
should validate the precondition and analyse the rest of `get_rcvbuf`, and WP should be able to
prove the call.

### Actual behaviour

Eva reports the precondition as invalid and considers the call non-terminating, so nothing after
it is analysed:

```text
[  Alarm  ] Instance of 'Pre-condition for 'other_options' 'optval_null_or_valid'' at initialization of 'r' ("g.c", line 11)
  NON TERMINATING FUNCTION
```

WP aborts:

```text
[wp] FRAMAC_SHARE/libc/sys/socket.h:398: User Error:
  Invalid infinite range (global L_opt_402)+(0..)
[kernel] Plug-in wp aborted: invalid user input.
```

Any level/option other than `SOL_SOCKET`/`SO_ERROR` goes through this behavior (`SO_RCVBUF`,
`TCP_INFO`, `SO_PEERCRED`, netlink options, ...).

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at 3dff90fc70; also 34.0~beta (Selenium)
- Plug-in used: libc specification (`share/libc/sys/socket.h`), with Eva and WP
- OS name: Debian GNU/Linux
- OS version: 13 (trixie)

### Additional information (optional)

**Cause.** `share/libc/sys/socket.h:395-405`, behavior `other_options` of `getsockopt`:

```c
    requires optval_null_or_valid:
      optval == \null || \valid(((char*)optval)+(0..));
    assigns ((char*)optval)[0..], \result
```

The range `(0..)` has no upper bound, so the precondition asks for an infinitely large valid
block, which no object satisfies. The default `assigns` (line 380) has the same unbounded range.
The neighbours already bound their buffers: `setsockopt` requires
`\valid_read(((char *)optval)+(0..optlen-1))` (line 551) and `getsockname` requires
`\valid(((char*)address)+(0 .. *address_len-1))` (line 361).

**Fix.** Bound the range by `*optlen` in the `requires` and in the two `assigns` clauses on
`optval`: `\valid(((char*)optval)+(0 .. *optlen-1))`, `((char*)optval)[0 .. *optlen-1]`. A null
`optval` stays allowed, `*optlen == 0` gives an empty range, and behavior `so_error` is unchanged.
With that contract:

```text
[  Valid  ] Instance of 'Pre-condition for 'other_options' 'optval_null_or_valid'' at initialization of 'r' ("g.c", line 11)
  r ∈ {-1; 0}
[wp] Proved goals:    8 / 8
```

and a call that claims more bytes than the buffer holds (`-cpp-extra-args=-DOPTLEN=8` on a 4-byte
`int`) is still reported invalid. (With the default Typed model, WP's proof of the bounded
precondition on an `int` cast to `char *` is a separate matter of the memory model; the reproducer
uses `-wp-model Bytes`.)

**Other unbounded ranges in the libc specification.** A scan of the ACSL clauses under
`share/libc` on `3dff90fc70` (other than `assigns`, `\from` and `reads`, where an unbounded range
is a sound over-approximation) finds:

| Function | Clause |
|---|---|
| `getsockopt` | `sys/socket.h:397-398`: `requires optval_null_or_valid: optval == \null \|\| \valid(((char*)optval)+(0..))` |
| `strtok_r` | `string.h:353-355`: `requires separation: \separated(..., *saveptr+(0..))` |
| `wcschr`, `wcspbrk`, `wcsrchr`, `wcsstr` | `wchar.h:109-110`, `200-201`, `208-209`, `225-226`: `ensures ... \result == \null \|\| \subset(\result, wcs+(0..))` |

Only the `getsockopt` clause is unsatisfiable. The `strtok_r` and `wcschr` contracts are accepted
by Eva (`separation` valid) and WP (`-wp-model Bytes`: all goals proved for a `strtok_r` caller and
a `wcschr` caller). All of them make E-ACSL abort under `e-acsl-gcc -L` (unbounded ranges are
rejected with `Options.abort`); that is reported separately as an E-ACSL issue, and this fix does
not depend on it.

A merge request with a fix follows.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
