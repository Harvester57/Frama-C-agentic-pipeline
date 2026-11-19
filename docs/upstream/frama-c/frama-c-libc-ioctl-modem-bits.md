# Libc: `<sys/ioctl.h>` defines `TIOCMGET` and `TIOCMSET` but not the `TIOCM_*` modem-line bits

Draft for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).
**Filed on 2026-11-18** as [#2830](https://git.frama-c.com/pub/frama-c/-/work_items/2830), with its
fix as merge request [!58](https://git.frama-c.com/pub/frama-c/-/merge_requests/58), on the owner's
go-ahead ("File issue + MR"). Issue 41 of this folder, drafted the same day.

**Package:**
[issue text](./filing/41-libc-ioctl-modem-bits-issue.md),
[MR text](./filing/41-libc-ioctl-modem-bits-mr.md),
[reproducer](./repro/41-libc-ioctl-modem-bits.sh) with its
[C file](./repro/41-libc-ioctl-modem-bits.c), and
[patch](./patches/41-libc-ioctl-modem-bits.patch) (validated on `master` `b80fcac74f`).

## Summary

Frama-C's `share/libc/sys/ioctl.h` defines the modem-control requests `TIOCMGET`, `TIOCMBIS`,
`TIOCMBIC`, `TIOCMSET` and `TIOCMIWAIT`, but none of the bits these requests read and write.
glibc's `<sys/ioctl.h>` defines eleven of them: `TIOCM_LE`, `TIOCM_DTR`, `TIOCM_RTS`, `TIOCM_ST`,
`TIOCM_SR`, `TIOCM_CTS`, `TIOCM_CAR`, `TIOCM_RNG`, `TIOCM_DSR`, `TIOCM_CD` and `TIOCM_RI`.

Any serial-port code that toggles RTS or DTR, or reads CTS or carrier detect, then stops the parse:

```
[kernel] src/modbus-rtu.c:254: User Error:
  Cannot resolve variable TIOCM_RTS
```

The requests are already there, so this is a gap in the same header rather than a missing feature:
a program cannot use `TIOCMGET` without these bits.

Found on libmodbus (`run-1`, 2026-11-18): the library's only product unit (`modbus-rtu.c`,
`modbus.c`, `modbus-tcp.c`, `modbus-data.c`) failed to parse, and the pipeline fell back to gcc for
the whole library. See the `TIOCM_RTS` entry of
[`../../troubleshooting/kernel-and-stubs.md`](../../troubleshooting/kernel-and-stubs.md).

## Eleven names, not fourteen

The first version of this draft asked for fourteen definitions. Measured in
`framac-master-audit:9540804` (Debian 13, glibc 2.41, gcc 14.2):

- **glibc:** `gcc -E -dM` on a file that only includes `<sys/ioctl.h>` prints eleven `TIOCM_*`
  names, `TIOCM_LE` to `TIOCM_RI`. They come from `<bits/ioctl-types.h>`, and `-std=c11 -pedantic`
  does not hide them.
- **Linux:** `<asm-generic/termios.h>` defines the same eleven with the same values, and three
  more: `TIOCM_OUT1` (`0x2000`), `TIOCM_OUT2` (`0x4000`) and `TIOCM_LOOP` (`0x8000`).
- **The three extra names are not visible through glibc:** after `<sys/ioctl.h>` and
  `<termios.h>`, gcc rejects each of them (`'TIOCM_LOOP' undeclared`). A program needs
  `<asm/termios.h>` or `<linux/termios.h>` to get them.

So the patch adds the eleven that a glibc program gets from `<sys/ioctl.h>`: with them, Frama-C
accepts what gcc accepts and nothing more. Both filing texts name the three others and offer to add
them. Only x86_64 headers were read; other architectures were not checked.

## Versions

| | Result |
|---|---|
| `35.0~~dev (Bromine)`, `master` at `b80fcac74f` (the audit image's tree moved to it and reinstalled) | **all eleven cases fail** (`Cannot resolve variable TIOCM_*`) |
| `35.0~~dev (Bromine)`, `master` at `95408044f7` (image `framac-master-audit:9540804` as built) | the six cases of the first reproducer failed (first draft), and the issue's `rts.c` fails; `sys/ioctl.h` is the same file as on `b80fcac74f` |
| `34.0~beta (Selenium)` (image `framac-analysis:latest`) | **all eleven fail**, identical output |
| `master` at `b80fcac74f` with the patch installed | `RESULT: fixed` |

Upstream `master` moved from `95408044f7` to `b80fcac74f` on 2026-11-17 (one merge,
`feature/blanchard/wp/dangling`: 15 files, all under `plugins/wp`). Nothing under `share/libc`,
`tests/libc` or `tests/variadic` changed, so the patch is the same on both.

## Reproduction

[`./repro/41-libc-ioctl-modem-bits.sh`](./repro/41-libc-ioctl-modem-bits.sh) parses
[`./repro/41-libc-ioctl-modem-bits.c`](./repro/41-libc-ioctl-modem-bits.c) once per name
(`-DCHECK_le`, `dtr`, `rts`, `st`, `sr`, `cts`, `car`, `rng`, `dsr`, `cd`, `ri`), with Frama-C's own
libc and with gcc. Frama-C stops at the first unknown name, hence one parse per name. On both
versions:

```
le: frama-c Cannot resolve variable TIOCM_LE; gcc ok
dtr: frama-c Cannot resolve variable TIOCM_DTR; gcc ok
rts: frama-c Cannot resolve variable TIOCM_RTS; gcc ok
st: frama-c Cannot resolve variable TIOCM_ST; gcc ok
sr: frama-c Cannot resolve variable TIOCM_SR; gcc ok
cts: frama-c Cannot resolve variable TIOCM_CTS; gcc ok
car: frama-c Cannot resolve variable TIOCM_CAR; gcc ok
rng: frama-c Cannot resolve variable TIOCM_RNG; gcc ok
dsr: frama-c Cannot resolve variable TIOCM_DSR; gcc ok
cd: frama-c Cannot resolve variable TIOCM_CD; gcc ok
ri: frama-c Cannot resolve variable TIOCM_RI; gcc ok
RESULT: bug present (11 of 11 checks fail)
```

Changes to the reproducer on 2026-11-18: it now covers the eleven names instead of six, the C file
no longer includes `<termios.h>` (glibc does not need it for these names) and initializes `flags`,
and the script also counts a non-zero exit of Frama-C as a failure.

## Fix

[`./patches/41-libc-ioctl-modem-bits.patch`](./patches/41-libc-ioctl-modem-bits.patch): one commit
on `b80fcac74f`, three files, 87 added lines.

- **`share/libc/sys/ioctl.h`:** the eleven definitions after `TIOCSER_TEMT`, next to the other bits
  of `TIOC*` requests:

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
  ```

- **`tests/libc/sys_ioctl_h.c`** and its oracle: an Eva test that uses the four requests and nine
  of the names in code, and asserts that the nine bits together are `0x1ff` and that `TIOCM_CD`
  and `TIOCM_RI` equal `TIOCM_CAR` and `TIOCM_RNG`. Both assertions are valid, with no alarm.
- **No contract change:** `ioctl` keeps its variadic specification.
- **No existing oracle changes.** `share/libc/__fc_libc.h` and the `fc_libc` oracles are not
  touched, so the patch does not overlap with !45 (26) or !56 (39).

### Validation

Run on 2026-11-18 in a container of `framac-master-audit:9540804` whose `master` was fast-forwarded
to `b80fcac74f`, rebuilt and reinstalled, with
[`../../../tools/upstream_audit/revalidate.sh`](../../../tools/upstream_audit/revalidate.sh)
`package 41`:

- **`git am --keep-non-patch`** applies the patch; author and committer are the GitLab noreply
  address; no file-mode change and no executable file.
- **New test against `master`'s `sys/ioctl.h`:** fails (`sys_ioctl_h.c:13: User Error: Cannot
  resolve variable TIOCM_CD`). With the patch it passes.
- **Suites, default configuration, with the patch:** `plugins/e-acsl/tests` (197 result logs),
  `tests/libc` (123) and, run by hand because `revalidate.sh` does not select it,
  `tests/variadic` (69; its `known/ioctl.c` includes the header). All pass with no difference.
- **`./dev/check-files.sh -p HEAD~1`:** passes (`Lint 3 file(s)`). The new test is also
  clang-format clean, after one reformatting of its last expression before the commit.
- **Reproducer on the installed patched tree:** eleven `frama-c ok; gcc ok` lines and `RESULT:
  fixed`.
- **The snippet of the issue text** (`rts.c`): `Cannot resolve variable TIOCM_RTS` at line 9 on
  unpatched `b80fcac74f` (the same text on the image's `95408044f7` install); with the patch it
  parses, and `-eva -main set_rts -lib-entry` reports 0 alarms. gcc compiles it, also with
  `-std=c11 -pedantic` and `-D_POSIX_C_SOURCE=200809L`: `<bits/ioctl-types.h>` has no feature-test
  guard.
- **Values:** a file of eleven `_Static_assert`s on the values is accepted by gcc with glibc and by
  the patched Frama-C.
- **Branch:** `make_branches.sh "41 fix/libc-ioctl-modem-lines"` reports `ok` (1 commit, 3 files,
  no mode change, base `b80fcac74f`); the commit is `03a454ea4b`, the one later pushed.

Not run: the rest of `tests/`, the default ptests of the other plugins, and the cram tests. The
test directory's configuration runs Eva with `-machdep x86_32`; no other machdep was tried.

A probe that did not work and is not in the texts: including Linux's `<asm-generic/termios.h>`
after Frama-C's `<sys/ioctl.h>` stops at `redefinition of 'winsize'`, with or without the patch
(both headers define the structure). The preprocessor gave no redefinition warning for the
`TIOCM_*` names in that run.

## Related, not requested

- **`TIOCM_OUT1`, `TIOCM_OUT2`, `TIOCM_LOOP`:** see "Eleven names, not fourteen".
- **termios2 requests** (`TCGETS2`, `TCSETS2`, `TCSETSW2`, `TCSETSF2`, from Linux
  `<asm-generic/ioctls.h>`): the same header stops at `TCGETS`/`TCSETS` (checked on both
  versions). libmodbus built with
  `HAVE_STRUCT_TERMIOS2` stops next at `Cannot resolve variable TCGETS2`. They encode
  `sizeof(struct termios2)`, a Linux UAPI type from `<asm/termbits.h>` that Frama-C's libc does not
  have, so they are left out: #2828 already asks which Linux headers are wanted. The filing texts
  do not mention them.
- **The `_IO`/`_IOR`/`_IOW`/`_IOWR` encoding** is already asked in #2828's inventory.

## Duplicates

Searched live on 2026-11-18 through the read-only API (`glab api`, issues and merge requests of
`pub/frama-c`, all states, title and description):

- `TIOCM`, `TIOCMGET`, `termios`, `modem`: no issue and no merge request.
- `ioctl`: only #2796 and !27 (package 03, the variadic fallback name), which are unrelated.
- `serial`: #28 (WP cache) and #1275 (closed, csmith), both unrelated.
- #2828 (package 39) lists the `_IO*` macros of `<sys/ioctl.h>` only, not these bits. On
  2026-11-18 it was open, with no label, no assignee and no comment; !56 and !45 had no comment
  either.

## Filing

- **Filed on 2026-11-18**, from the account Harvester57:
  - Upstream `master` was still `b80fcac74f` (`git ls-remote`) just before.
  - The branch `fix/libc-ioctl-modem-lines` was pushed to the fork from the saved bundle, as
    commit `03a454ea4b`. Its three blobs are the ones of the patch file.
  - `file_upstream.py issue 41` created #2830, `subst` wrote the number into the MR text, and
    `mr 41` created !58. Title and description of both were read back and are identical to the
    texts.
  - !58: one commit, three files, mergeable without conflict, source branch removed on merge,
    maintainers may push, no squash. No label, assignee or reviewer. The CONTRIBUTING and CLA
    checkboxes are left for the owner to tick.
  - Both stored descriptions were rendered through GitLab's markdown endpoint: no user mention,
    no strikethrough, every code block closed, and the links are #2828, #2830, !45 and !56.
  - `mr 41` ended with "CHECK FAILED": it read the commit list at once and got 0 commits. The
    merge request was correct (one commit a few seconds later). The script now waits for the
    commits as it does for the diff, and its CRLF check reads bytes (uncommitted).
- **A new issue, not a note on #2828:** the owner chose the new issue. The text stands alone and
  cites #2828 as related, because this gap needs no decision about Linux headers.
- **Branch:** `fix/libc-ioctl-modem-lines`, one commit from `b80fcac74f`, built in the audit
  container with
  [`../../../tools/upstream_audit/make_branches.sh`](../../../tools/upstream_audit/make_branches.sh)
  and pushed to the fork from its bundle. Two traps, for the next package:
  - **The image's `master` is still `95408044f7`.** In a fresh container, `make_branches.sh` would
    build the branch on the old base without saying so, while the MR text says `b80fcac74f`.
    First run, in the container:
    `git fetch https://git.frama-c.com/pub/frama-c.git master && git checkout -q master && git merge --ff-only FETCH_HEAD`
    (`git fetch origin master` fails in the image), and check that `master` is the head
    upstream has that day. If upstream moved again, look at what changed under `share/libc` and
    `tests/` and correct the "Based on" line of the MR text.
  - **The host clone needs the base too.** The bundle is made with `^master`, so the clone used
    for the push must have fetched `b80fcac74f` before `git fetch branches.bundle` works.
- **Order used:** `file_upstream.py issue 41`, then `subst` (the MR text held `#<issue>`), then
  `mr 41`.

## Pipeline workaround

[`../../../templates/fc_stubs/fc_compat_types.h`](../../../templates/fc_stubs/fc_compat_types.h)
defines fourteen bits (the eleven of the patch and the three Linux-only ones) and the four termios2
requests, each `#ifndef`-guarded, in its `__fc_libc` branch (force-included into every Eva, WP and
Phase 0 parse). It can go once a release carries the fix. Until then it is harmless beside a fixed
libc: its eleven common definitions are written like the patch's, and an identical redefinition is
not an error.

**To correct after libmodbus `run-1`:**
[`../../../templates/fc_stubs/README.md`](../../../templates/fc_stubs/README.md) says that glibc's
`<sys/ioctl.h>` defines `TIOCM_LE` to `TIOCM_LOOP`. It defines `TIOCM_LE` to `TIOCM_RI`; the three
others need `<asm/termios.h>` with gcc and glibc (checked: it includes `<asm-generic/termios.h>`,
and gcc then accepts them), so the pipeline header lets Frama-C accept three names that gcc may
reject. The sentence was not changed on 2026-11-18, because the cache key digest
(`scripts_digest` in [`../../../scripts/cache.py`](../../../scripts/cache.py)) covers every file
under `templates/` and a run was going. The comment in `fc_compat_types.h` itself is right.
