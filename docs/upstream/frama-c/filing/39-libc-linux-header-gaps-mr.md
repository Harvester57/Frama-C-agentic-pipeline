# [libc] add Linux headers sys/epoll.h and sys/inotify.h

- Source branch: `feature/libc-epoll-inotify` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `95408044f7`. Patch: [`../patches/39-libc-linux-header-gaps.patch`](../patches/39-libc-linux-header-gaps.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #2828.

## Problem

Frama-C's libc has no `<sys/epoll.h>` and no `<sys/inotify.h>`. A Linux program with an epoll event
loop or an inotify watcher stops at the include (`fatal error: sys/epoll.h: No such file or
directory`).

## Change

Two new Linux-specific headers, in the style of `sys/sendfile.h` and `sys/prctl.h` (`// Non-POSIX;
Linux-specific`, `__PUSH_FC_STDLIB`, `__BEGIN_DECLS`).

**`share/libc/sys/epoll.h`**

- Constants:
  - the `EPOLL*` event bits;
  - `EPOLL_CTL_ADD`, `EPOLL_CTL_DEL` and `EPOLL_CTL_MOD`;
  - `EPOLL_CLOEXEC`, which equals `O_CLOEXEC`.
- `epoll_data_t` and `struct epoll_event`. The struct is `__attribute__((__packed__))` under
  `#ifdef __x86_64__`, like glibc's `__EPOLL_PACKED` and the kernel ABI: 12 bytes on x86_64.
- `epoll_create` (`size > 0`) and `epoll_create1`: the result is `-1` or a descriptor below
  `__FC_MAX_OPEN_FILES`.
- `epoll_ctl`:
  - valid descriptors and a valid `op`;
  - `\valid_read(event)` unless the op is `EPOLL_CTL_DEL`, where the kernel ignores it and `NULL` is
    usual;
  - the result is `0` or `-1`.
- `epoll_wait` and `epoll_pwait`:
  - `\valid(events + (0 .. maxevents - 1))`, `maxevents > 0`, and a `sigmask` that is null or
    readable;
  - the `full` / `partial_timeout_or_error` behaviours of `read()`, on `Frama_C_entropy_source`.
    The result is `maxevents`, or in `[-1 .. maxevents - 1]`, and the first `\result` events are
    initialized.
- The kernel's interest list is a `//missing:` comment.

**`share/libc/sys/inotify.h`**

- `struct inotify_event`, with a flexible `name[]`.
- Every `IN_*` constant, including `IN_CLOEXEC` and `IN_NONBLOCK` (the `O_*` values).
- `inotify_init`, `inotify_init1`, `inotify_add_watch` (`valid_read_string(pathname)`, result `-1`
  or `>= 0`) and `inotify_rm_watch` (result `0` or `-1`).
- The watch list is a `//missing:` comment.

All values, sizes, member offsets and prototypes match glibc 2.41. A file of `_Static_assert`s
passes both with gcc and glibc and with Frama-C and these headers.

**Tests and oracles**

- Both headers are added to `share/libc/__fc_libc.h` and `tests/libc/fc_libc.c`, as
  `tests/libc/check_full_libc.sh` requires.
- New Eva tests `tests/libc/sys_epoll_h.c` and `tests/libc/sys_inotify_h.c`, with their oracles.
  Every precondition and assertion is valid, and there is no alarm.
- `tests/libc/oracle/fc_libc.0.res.oracle` and `fc_libc.2.res.oracle` gain two lines each, the new
  `#include` and `Parsing` lines. No other oracle moves.
- !45 also changes `fc_libc.0.res.oracle`, on other lines. Whichever MR lands second may need the
  oracle regenerated.

**Two choices you may want to change**

- The packed attribute. Frama-C warns `kernel:typing:addr-of-packed-field` when code takes
  `offsetof(struct epoll_event, data)`, which gcc does not, so the test checks `sizeof` only.
  Without the attribute the structure would be 16 bytes, which is not the ABI.
- Reading the events after a full `epoll_wait`. Eva still reports an initialization alarm on
  `evs[i]`, because the two behaviours are joined. This is what `read()` gives on the same pattern,
  so I kept its contract shape rather than invent another one.

## Testing

On a build of `95408044f7` with the patch (Debian 13, OCaml 5.5 switch, gcc 14.2, glibc 2.41):

- **Reproducer from the issue:** before, `fatal error` on both files. After, both parse and Eva
  reports no alarm.
- **New tests on master:** the new tests and oracles alone on `95408044f7` fail with `fatal error:
  sys/epoll.h: No such file or directory` (and `sys/inotify.h`). With the patch they pass.
- **`tests/libc`:** `dune build @tests/libc/ptests_config` passes after promotion. Only the two
  `fc_libc` oracles changed. `tests/libc/check_full_libc.sh ../../share/libc` passes.
- **Wider ptests, default configuration:** all three pass with no difference:
  - `@tests/ptests_config` (all of `tests/`, 1149 results);
  - `@plugins/eva/tests/builtins/ptests_config` (62 results);
  - `@plugins/e-acsl/tests/ptests_config` (197 results).

  These ran in one `dune build`. Results whose dependencies did not change may come from dune's
  cache.
- **Not run:**
  - the default ptests of the other plugins;
  - E-ACSL's `dev` configuration (it compiles and runs the instrumented tests);
  - the cram tests.

  `git grep -l -e __fc_libc.h -e sys/epoll.h -e sys/inotify.h -- tests plugins src` hits only
  `tests/libc`, so no other test includes the new headers. In `share/`, `__fc_libc.h` is read by
  `analysis-scripts/estimate_difficulty.py` (and its `.mk`). That script will now see the two
  headers as provided by the libc. Its cram tests (`tests/fc_script`) were not run.
- **WP:** not run on the new contracts. The tests are Eva tests, like those of the neighbouring
  Linux headers.
- **`./dev/check-files.sh -p HEAD~1`:** clean (`Lint 10 file(s)`). `share/**` and `tests/**` C files
  are `-check-indent` in `.gitattributes`, so clang-format is not applied to them. The two test
  files are nonetheless clang-format clean.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
