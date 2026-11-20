# MetAcsl with E-ACSL: libc calls get no `\writing` instance and no warning; an overflow is reported by the instance's guard at `<unknown>:0`

Draft for the **MetAcsl** issue tracker (https://git.frama-c.com/pub/meta/-/issues, project id
869), not for `pub/frama-c`. **Not filed.** Package 49 of this folder, drafted on 2026-11-20. It is
a feature request with a merge request for its first point.

**Package:**
[issue text](./filing/49-metacsl-eacsl-libc-instances-issue.md),
[MR text](./filing/49-metacsl-eacsl-libc-instances-mr.md),
[patch](./patches/49-metacsl-eacsl-libc-instances.patch) (one `git format-patch` commit on
`pub/meta` `master` `4f43801390`),
[reproducer](./repro/49-metacsl-eacsl-libc-instances.sh) with its
[C file](./repro/49-metacsl-eacsl-libc-instances.c).

## Summary

1. `e-acsl-gcc` parses with the system headers (`-no-frama-c-stdlib`), so `memcpy` and the rest of
   the libc have no specification. MetAcsl gives a `\writing` property no instance at
   `memcpy(&protected, ...)` and prints nothing: its warning `Cannot analyze footprint of function
   ...` only fires for a behavior without `assigns`, and a function declared without any
   specification has no behavior. The E-ACSL binary runs clean on a write that WP and Eva (Frama-C
   libc) see. `e-acsl-gcc -L` gives the call its instance.
2. With an `assigns` on `memcpy` (written by hand, or from `-L`), an overflowing `memcpy` is
   reported by E-ACSL's validity guard of the instance's `\separated`, at `<unknown>:0`, instead of
   by E-ACSL's `memcpy` replacement (`memcpy: insufficient space in destination space`). The same
   `\separated` written by hand is reported at its line, so the missing location comes from the
   term MetAcsl builds from the callee's `assigns`.

## Where the pipeline meets it

The E-ACSL fuzz build runs MetAcsl in a stage of its own before RTE and E-ACSL
(`meta_stage_flags`, `EACSL_META_FLAGS` in
[`../../../scripts/eacsl_toolchain.py`](../../../scripts/eacsl_toolchain.py)). Both parts are in
[`../../troubleshooting/eacsl-and-fuzzing.md`](../../troubleshooting/eacsl-and-fuzzing.md), section
"MetAcsl Properties in the E-ACSL Build" (symptoms "A Write Through `memcpy` Into a
`\writing`-Protected Global Runs Clean in the E-ACSL Build" and "An Out-of-Bounds `memcpy`
Changes Its Fingerprint to `<unknown>:0: E-ACSL RTE failed`..."), and in
[`../../plans/metacsl-exploitation-plan.md`](../../plans/metacsl-exploitation-plan.md). The
pipeline's workaround, which stays whatever upstream answers:

- [`../../../templates/metacsl/eacsl_libc_writers.h`](../../../templates/metacsl/eacsl_libc_writers.h):
  `assigns` contracts for `memcpy`, `memmove`, `memset`, `strncpy`, appended to the E-ACSL meta
  file by `fuzz_build.eacsl_security_meta_text`. **Not to be upstreamed** (owner's decision): they
  are glibc-specific. The issue mentions them only to show that the idea works.
- `eacsl_meta_guarded_text`: each `\writing` predicate becomes `\valid(\written) ==> (P)`, each
  `\reading` one `\valid_read(\read) ==> (P)`, in the E-ACSL meta file only.
- `EACSL_META_LIBC_UNCHECKED` and `security_props.libc_unchecked` list the other libc writers,
  which stay unchecked.

The fuzz builds use `-M` (`--full-mtracking`) and `--libc-replacements`; the reproducer does too.

## Evidence

Run on 2026-11-20 in `framac-analysis:latest` (Frama-C 34.0~beta, MetAcsl 0.12~beta, gcc 14),
with [`./repro/49-metacsl-eacsl-libc-instances.sh`](./repro/49-metacsl-eacsl-libc-instances.sh):

```
34.0~beta (Selenium)
frama-c, Frama-C libc:          instance at memcpy: yes
frama-c, system headers:        instance at memcpy: no, footprint warnings: 0
e-acsl-gcc, write:              exit 0
e-acsl-gcc -L, write:           exit 134, 49-metacsl-eacsl-libc-instances.c:39: Error: Assertion failed:
overflow, no property:          exit 134, memcpy: insufficient space in destination space , at least 8 bytes required
overflow, contract:             exit 134, <unknown>:0: Error: E-ACSL RTE failed:
overflow, -L:                   exit 134, <unknown>:0: Error: E-ACSL RTE failed:
overflow, assertion by hand:    exit 134, 49-metacsl-eacsl-libc-instances.c:17: Error: E-ACSL RTE failed:
overflow, contract, guarded:    exit 134, memcpy: insufficient space in destination space , at least 8 bytes required
write, contract, guarded:       exit 134, 49-metacsl-eacsl-libc-instances.c:35: Error: Assertion failed:
RESULT: the call without specification is skipped silently
```

With the patch (MetAcsl `master` `4f43801390` plus the patch, built with dune and installed in a
throwaway container of the same image, with the `PLpointer_comparable` line of `meta_parse.ml`
removed for the 34.0~beta kernel), the second line reads `footprint warnings: 1`, the result line
`RESULT: the call without specification is reported (no-footprint warning)`, and every other line
is the same.

Other observations from the same session (scratch runs, not in the reproducer):

- **The warning exists, for the other case.** A `memcpy` declared with `/*@ requires \true; */`
  and no `assigns` gives `[meta] Warning: Cannot analyze footprint of function memcpy: no assigns
  clause. ...` and no instance. The printed host declaration of `memcpy` has no specification at
  all.
- **The overflow does reach `auth_ok`.** With `--e-acsl-extra -e-acsl-no-rte-mem` the unguarded
  instance is evaluated and fails as `auth_state/meta` at line 39: `out` is at `...274` and
  `auth_ok` at `...278`. So the meta assertion is not wrong to fail; the request is about which
  report a user gets and its location. `-e-acsl-rte 0` gives the same.
- **`-meta-separate-annots`** does not change the order: the guard still fails first, now located
  in E-ACSL's temporary `.i` file.
- **Without `-M`:** `--libc-replacements` aborts on the correct `memcpy(&auth_ok, ...)` with
  `memcpy: destination space  space unallocated or cannot be written`, with or without
  properties; without `--libc-replacements` (and without `-M`) the overflow runs clean (no
  `memcpy` check at all).
  The issue states the flags it uses and mentions the first point as a separate E-ACSL question.

## Cause

- `meta_annotate.ml` (MetAcsl `master`, same git blob `03447cfd` as the installed file), class
  `writing_visitor`, `vstmt_aux`: a call to a function without definition goes to
  `inspect_contract self#external_assigns` when `-meta-check-ext` is on (default). The reading
  visitor uses `inspect_contract self#passthrough_from` the same way.
- `inspect_contract` iterates `Annotations.iter_behaviors` over the callee and warns on
  `WritesAny`. A prototype from the system headers has no behavior, so nothing runs and nothing
  is printed. The README's sentence "if `g` does not specify a memory footprint, it is
  **assumed** that it respects all related meta-properties" is honoured, silently.
- `unknown-func` (aborts by default) is about names in `\targets` (`meta_deduce.ml`, the target
  computation), not about callees; it does not cover this.
- Part 2: E-ACSL evaluates `\separated` only on valid operands and adds a `\valid_read` guard per
  operand; the guard is located where its term is. In the `-L` build's instrumented file the
  guard of `&auth_ok` (written in the property) has the property's line, and the guard of the
  range built from `memcpy`'s `assigns` (`writing_instance`, `addr_of_tlval`) has
  `file = "<unknown>"`, `line = 0`. Not checked in the OCaml: which constructor drops the
  location.

## Tracker choice: one issue, on `pub/meta`

The three things that can be asked for are MetAcsl changes: the warning (patched), a location for
the substituted terms, and an option for validity-guarded instances. On the E-ACSL side nothing is
broken: `e-acsl-gcc -L` already gives MetAcsl the libc contracts. Its cost is real (the E-ACSL
user manual warns that translating the libc contracts adds run-time overhead, and an unbounded
range in a libc contract aborts the whole instrumentation, pub/frama-c#2798 for `strtok_r`,
`getsockopt`, `wcschr`, ...), but a request for an "`-L` for the specs, not for the
instrumentation" mode is a design question; it is asked at the end of the MetAcsl issue, with an
offer to file it on `pub/frama-c` if the maintainers prefer. A separate `[e-acsl-gcc]` issue with
no defect to show would get a one-line answer pointing at `-L`.

Title tag: `[MetAcsl]`, as 47 and 48; issue 45, also for `pub/meta`, has no tag. They should be
aligned before filing.

## Patch

[`./patches/49-metacsl-eacsl-libc-instances.patch`](./patches/49-metacsl-eacsl-libc-instances.patch),
author `Florian Stosse <1315-Harvester57@users.noreply.git.frama-c.com>`, on `pub/meta` `master`
`4f43801390` (`git apply --check` clean; after 47's and 48's patches, `git am --3way` merges
`meta_annotate.ml` cleanly and conflicts on one line of `CHANGELOG.md` only, where 47 adds its
own entry at the same place): `inspect_contract` warns when the callee has no
behavior; new warning category `no-footprint` for both warnings; README and CHANGELOG sentences;
new test `tests/meta/no_footprint.i` with oracles for the default and `fold` configurations
(generated with the test's command line, since `make tests` does not run in the image). The MR
text lists what was run: the `OPT` lines of `tests/meta` (21 runs, full output) and of
`tests/meta-wp` and `tests/meta-deduce` (15 runs, `[meta]` lines) are unchanged. Not run: `make
tests`, the `fold` configuration of the existing tests, `ocp-indent`, MetAcsl's CI. Subject
prefix `[meta]`, as 47's patch.

No patch for parts 2 and 3 of the proposal: the location fix needs the right place in
`writing_instance` / `addr_of_tlval` and a decision on which location (call or property) the
maintainers want, and the guarded-instance option is a design choice (it moves an overflow that
hits the protected object from the property to the memory check).

## Duplicate check (2026-11-20)

- `pub/meta` (project 869), all issues: #1 (closed, conflicting global and formal names), #3
  (closed, `\written` on a bitfield), #4 (open, labels in calling contexts with `switch`). None
  is about callees without specification, E-ACSL or locations.
- `pub/frama-c` (project 780), searches `libc`, `memcpy`, `MetAcsl`, `meta`, `assigns`,
  `e-acsl-gcc stdlib`, `frama-c-stdlib`, `separated`: nothing on MetAcsl instances at libc calls.
  Related, not duplicates: #2674 (consistency of `\from` uses between WP and MetAcsl), #2724
  (E-ACSL instrumentation time with RTE on large code), #2759 (bypassing Frama-C libc headers),
  #2798 (ours: unbounded ranges abort E-ACSL, cited for `-L`), #2803 (ours: `memcmp` with
  `--libc-replacements`).
- In this folder: 45 (`\result` in `\postcond`, other topic), 47 (the `\written` instance at a
  call keeps the callee's `Old` / `Pre` labels, which is what makes E-ACSL abort on `strcpy`'s
  contract; cited in the issue as `#ISSUE-47`, not repeated), 48 (`-meta-fold` instances have
  no location: the location of the folded assertion; this package is about terms inside an
  unfolded instance, cited as `#ISSUE-48`).

## Related findings not in this package

- **MetAcsl: the formals of a contract on a later declaration are not substituted.** Candidate
  for its own number. With `v1.c` (`#include <string.h>`, `int auth_ok;`,
  `process` calling `memcpy(&auth_ok, in, sizeof auth_ok)`) and `v2.c` (the `\writing` property,
  and `/*@ assigns ((char *)d)[0 .. n - 1] \from ((char *)s)[0 .. n - 1]; assigns \result \from
  d; */ extern void *memcpy(void *restrict d, const void *restrict s, size_t n);`),
  `frama-c -machdep gcc_x86_64 -no-frama-c-stdlib v1.c v2.c -meta -then-last -print` prints the
  instance `\separated((char *)__dest + (0 .. __n - 1), &auth_ok)`: glibc's formal names, not the
  call's arguments. `e-acsl-gcc` then fails with `'__dest' undeclared`. The same contract in the
  same file as the call (`#include <string.h>` then the redeclaration with `d`, `s`, `n`) is
  substituted correctly. Probable cause, not checked: `inspect_contract` maps formals by name,
  taking the names from `Kernel_function.get_type` (here apparently `d`, `s`, `n`), while the
  contract's terms were renamed to the kernel function's formals (`__dest`, `__n`). This is why
  the pipeline's `eacsl_libc_writers.h` uses glibc's names. Not related to pub/meta #1
  (a global and a formal with the same name).
- **E-ACSL: `--libc-replacements` without `-M` aborts on a correct `memcpy` into a global**
  (`memcpy: destination space  space unallocated or cannot be written`). Not checked whether this
  is known or intended (the replacement needs the destination tracked).

## Filing

- Target: `pub/meta`. [`../../../tools/upstream_audit/file_upstream.py`](../../../tools/upstream_audit/file_upstream.py)
  files on `pub/frama-c` (project 780) only, so this one is filed by hand.
- Placeholders to replace before sending: `#<issue>` in the MR text, `#ISSUE-47` and `#ISSUE-48`
  (both `pub/meta`) in the issue text. File 47 and 48 first.
- Filing is paused until the maintainers answer #2832, like 45.
