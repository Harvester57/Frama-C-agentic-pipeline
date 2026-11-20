# MetAcsl with E-ACSL: libc calls get no `\writing` instance and no warning; out-of-bounds writes fail in RTE guards at `<unknown>:0`

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
   by E-ACSL's `memcpy` replacement (`memcpy: insufficient space in destination space`). An
   ordinary out-of-bounds C pointer write (`*p = 1;`, with no libc and no callee contract) fails
   at `<unknown>:0: Error: E-ACSL RTE failed: \valid_read(p)` the exact same way, while the same
   `\separated` written by hand is reported at its line: `meta_annotate.ml` builds every `\written`,
   `\read`, and `\called` term without `~loc` (`addr_of_tlval` and `Logic_const.term` default to
   `Kernel.gen_loc`, which E-ACSL prints as `<unknown>:0`).

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
e-acsl-gcc -L, write:           exit 134, 49-metacsl-eacsl-libc-instances.c:51: Error: Assertion failed:
overflow, no property:          exit 134, memcpy: insufficient space in destination space , at least 8 bytes required
overflow, contract:             exit 134, <unknown>:0: Error: E-ACSL RTE failed:
overflow, -L:                   exit 134, <unknown>:0: Error: E-ACSL RTE failed:
overflow, plain *p = 1:         exit 134, <unknown>:0: Error: E-ACSL RTE failed:
overflow, assertion by hand:    exit 134, 49-metacsl-eacsl-libc-instances.c:24: Error: E-ACSL RTE failed:
overflow, contract, guarded:    exit 134, memcpy: insufficient space in destination space , at least 8 bytes required
write, contract, guarded:       exit 134, 49-metacsl-eacsl-libc-instances.c:47: Error: Assertion failed:
RESULT: the call without specification is skipped silently
```

With the patch (MetAcsl `master` `4f43801390` plus the patch, built with dune and installed in a
throwaway container of the same image, with the `PLpointer_comparable` line of `meta_parse.ml`
removed for the 34.0~beta kernel), the second line reads
`instance at memcpy: no, footprint warnings: 1 (49-metacsl-eacsl-libc-instances.c:29)`, the result
line `RESULT: the call without specification is reported (no-footprint warning)` (exit 0), and
every other line is the same.

Other observations from the same session (scratch runs, not in the reproducer):

- **The warning exists, for the other cases.** A `memcpy` declared with `/*@ requires \true; */`
  and no `assigns` gives `Cannot analyze footprint of function memcpy: no assigns clause. ...` and
  no instance; an `assigns *p;` without `\from` under `\reading` gives `Cannot fully analyze read
  footprint of function ...: no \from part in some assigns clauses.` Neither carried a warning
  category or call-site location before the patch. The printed host declaration of `memcpy` has no
  specification at all.
- **Plain `*p = 1;` instrumented guards.** In the E-ACSL instrumented C file for `-DOVERFLOW_PTR`
  (`int out_i[4]; process(out_i + 10);` with `*p = 1;`), both `\aligned(p,4)` and `\valid_read(p)`
  are emitted with `file = "<unknown>"` and `line = 0`; at run time `\valid_read(p)` aborts at
  `<unknown>:0: Error: E-ACSL RTE failed`.
- **The `memcpy` overflow does reach `auth_ok`.** With `--e-acsl-extra -e-acsl-no-rte-mem` the
  unguarded instance is evaluated and fails as `auth_state/meta` at the property line: `out` sits
  adjacent to `auth_ok` in memory. So the meta assertion is not wrong to fail; the request is about
  which report a user gets and its location. `-e-acsl-rte 0` gives the same.
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
- In `reading_visitor#passthrough_from` (line 781), `FromAny` warns with `~once:true`, also
  without a warning category or call-site location.
- `unknown-func` (aborts by default) is about names in `\targets` (`meta_deduce.ml`, the target
  computation), not about callees; it does not cover this.
- Part 2: E-ACSL evaluates `\separated` only on valid operands and adds a `\valid_read` (and
  `\aligned`) guard per operand; the guard takes its location from the term it guards. In the `-L`
  build's instrumented file the guard of `&auth_ok` (written in the property) has the property's
  line, while the guard of the `\written` term has `file = "<unknown>"`, `line = 0` — both for
  `memcpy`'s `assigns` range and for an ordinary `*p = 1;` write. Verified in `meta_annotate.ml`
  and Frama-C 34.0's `logic_utils.ml` / `logic_const.ml`:
  - `addr_of_tlval` (`meta_annotate.ml:487-506`, called for `\written`, `\lhost_written`, `\read`,
    `\lhost_read`, and `\called` at lines 515, 634-635, and 723-724) calls
    `Logic_utils.mk_logic_AddrOf` (and in the bitfield branch `Logic_utils.mk_cast`,
    `Logic_const.term`, and `Logic_const.tinteger`) without passing `~loc`.
  - `writing_instance` (`meta_annotate.ml:640`) and `reading_instance` (`meta_annotate.ml:729`)
    also call `Logic_const.term (TLval ...)` without `~loc` (for `*\written` and `*\read`).
  - Both `Logic_utils.mk_logic_AddrOf` (`logic_utils.ml:197`) and `Logic_const.term`
    (`logic_const.ml:152`) default `~loc` to `Kernel.gen_loc` (`Fileloc.generated "kernel"`, no
    source file or line, printed by E-ACSL as `<unknown>:0`). Even in `mk_logic_AddrOf`'s
    `TMem e, TNoOffset` branch (`*p`), it executes `Logic_const.term ~loc e.term_node e.term_type`,
    discarding `e.term_loc` and replacing it with `Kernel.gen_loc`.
  - Therefore every `\written`, `\read`, and `\called` term — whether from a plain C assignment or
    read (`Logic_utils.lval_to_term_lval` at lines 685, 691, 766) or from a callee's
    `assigns`/`\from` contract (`external_assigns` / `passthrough_from`) — loses its location,
    unlike `\func` at line 371 which passes `~loc` (`Property.location ump.ump_ip`).

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

Title convention: no `[MetAcsl]` prefix in the issue title, matching `pub/meta` tracker issues #1,
#3, #4, and draft 45.

## Patch

[`./patches/49-metacsl-eacsl-libc-instances.patch`](./patches/49-metacsl-eacsl-libc-instances.patch),
author `Florian Stosse <1315-Harvester57@users.noreply.git.frama-c.com>`, on `pub/meta` `master`
`4f43801390` (`git apply --check` clean on pristine `4f43801390`):

- `meta_options.ml` / `.mli`: new warning category `no-footprint` (default status: warning).
- `meta_annotate.ml`: `inspect_contract` warns when the callee has no behavior, sharing a
  `no_footprint` helper with `WritesAny` using `~once:true ~loc:(Cil_datatype.Stmt.loc stmt)
  ~wkey:Meta_options.no_footprint_wkey`; `reading_visitor#passthrough_from` adds
  `~loc:(Cil_datatype.Stmt.loc stmt) ~wkey:Meta_options.no_footprint_wkey` to its existing
  `FromAny` warning (keeping `~once:true`).
- `README.md` (`\writing` and `\reading` contexts) and `CHANGELOG.md`: document `no-footprint` and
  call-site locations.
- New test `tests/meta/no_footprint.i` covering both `\writing` (`f_write`) and `\reading`
  (`f_read`) across four callees (`copy` with no specification, `touch` with `WritesAny`,
  `assign_only` with `assigns *p;` / `FromAny`, and `copy_spec` with `assigns ... \from ...`), run
  with default status (`.0`) and `-meta-warn-key no-footprint=inactive` (`.1`), with all four
  oracles (`oracle/` and `oracle_fold/`) generated with `frama-c -check`.

Verified in throwaway containers of `framac-analysis:latest` (with the 1-line
`PLpointer_comparable` removal in `meta_parse.ml` inside the container build only, not in the
patch): all 76 `frama-c-ptests`-generated commands across `tests/meta` (21 existing + 2 new,
default and `fold`), `tests/meta-wp` (12 default + 12 `fold`), and `tests/meta-deduce` (3 default
+ 3 `fold`) were run before and after the patch. Zero unintended diffs across all 72 existing
runs (all 42 existing `tests/meta` default and `fold` runs match their committed upstream oracles
byte-for-byte, and zero existing tests emit any `no-footprint` warning). All four `no_footprint.i`
runs fail before the patch and match their oracles after; extra checks verified `no-footprint=error`
(exit 1), `no-footprint=once` (single global warning), and multi-clause `FromAny` across two call
sites (one warning per call site). Not run: `dune build @ptests` directly (the image strips Frama-C
doc/man files), SWI-Prolog deduction checks, `ocp-indent`, MetAcsl's CI. Subject prefix `[meta]`,
as 47's patch.

No patch for parts 2 and 3 of the proposal: the location fix needs a decision on which location
(statement or property) the maintainers want in `addr_of_tlval` and `writing_instance` /
`reading_instance`, and the guarded-instance option is a design choice (it moves an overflow that
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
