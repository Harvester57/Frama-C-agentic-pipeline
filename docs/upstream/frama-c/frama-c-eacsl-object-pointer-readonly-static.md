# E-ACSL: `\object_pointer(p)` is false at run time for a pointer to read-only data (string literal, `const` global array), so every `-warn-invalid-pointer` guard on it fails

Draft bug report for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).
**Not filed.** Number 29 in this folder's [index](./README.md).

**Filing package (2026-11-16):** issue text
[`./filing/29-eacsl-object-pointer-readonly-static-issue.md`](./filing/29-eacsl-object-pointer-readonly-static-issue.md),
merge request text
[`./filing/29-eacsl-object-pointer-readonly-static-mr.md`](./filing/29-eacsl-object-pointer-readonly-static-mr.md),
patch [`./patches/29-eacsl-object-pointer-readonly-static.patch`](./patches/29-eacsl-object-pointer-readonly-static.patch)
(validated, see "Validation" below), reproducer
[`./repro/29-eacsl-object-pointer-readonly-static.sh`](./repro/29-eacsl-object-pointer-readonly-static.sh)
with [`./repro/29-eacsl-object-pointer-readonly-static.c`](./repro/29-eacsl-object-pointer-readonly-static.c)
(`direct.c` below) and
[`./repro/29-eacsl-object-pointer-readonly-static-rte.c`](./repro/29-eacsl-object-pointer-readonly-static-rte.c)
(`five.c` below without `<stdio.h>`, so that it also runs with `-m bittree`, see "Also seen").

**Related, not the same bug:** Issue 27 ([#2794](https://git.frama-c.com/pub/frama-c/-/work_items/2794),
merge request [!26](https://git.frama-c.com/pub/frama-c/-/merge_requests/26)) is about how const
globals are *marked* read-only. This one is about `\object_pointer` treating a block that is correctly
marked read-only as no object at all. !26 does not change it: arrays and string literals were already
marked through their address before !26.

## Summary

The ACSL manual (section 2.7.1) says: "`\object_pointer{L}(s)` indicates that each element of s
either points to an element of an array object whose lifetime includes the program point denoted by L
or one past the last element of such an array object." Nothing in it asks the object to be writable.

E-ACSL's runtime implements it with `\valid`, which is false for a read-only block. So, in a monitored
program, `\object_pointer(p)` is false for every pointer into a string literal or a `const` global
array, although `\valid_read(p)` holds on the same pointer.

It matters most with `-warn-invalid-pointer`: the RTE guard E-ACSL then generates for every pointer
value, `\null == p || \object_pointer(p)` (named `invalid pointer`), fails as soon as a function walks a
string literal or a constant table. On two real code bases this made the option unusable:

- minmea: 371 of 372 inputs abort at `while (*format)` in `minmea_scan`, where `format` is a format
  string literal;
- nettle (SHA-3): 15 of 24 inputs abort on `&nettle_sha3_permute_rc[i]`, a `static const` table.

## Versions

- Reproduced on `34.0~beta (Selenium)` (image `framac-analysis:latest`, clang 19.1.7) and on
  `35.0~~dev (Bromine)`, `master` at `3dff90fc70` (2026-11-13). `git ls-remote` on 2026-11-16 shows
  that commit is still `master`'s head. Same results on both.
- `eacsl_object_pointer` came with `f4db1ffd0b` ("[e-acsl] implement built-in predicate
  `\object_pointer`", committed 2025-03-28); `git tag --contains` lists 31.0 onwards. Releases before
  34 were not run. The function and `eacsl_valid` are identical in 34.0-beta and `3dff90fc70`.
- 2026-11-16: the reproducer script was rerun on `framac-master-audit:3dff90f` (`master` `3dff90fc70`)
  and `framac-analysis:fc34` (34.0~beta) with identical output, and the fix was validated on
  `3dff90fc70` (image `framac-master-audit:3dff90f-p29`).

## Reproduction

Direct form, no RTE needed (`direct.c`):

```c
static const char const_table[4] = {1, 2, 3, 0};
static char plain_table[4] = {1, 2, 3, 0};

static void check(const char *p) {
  /*@ assert \valid_read(p); */
  /*@ assert \object_pointer(p); */
}

int main(int argc, char **argv) {
  char local[4] = {1, 2, 3, 0};
  int which = argc > 1 ? argv[1][0] - '0' : 0;
  if (which == 0) check(local);
  if (which == 1) check(plain_table);
  if (which == 2) check(const_table);
  if (which == 3) check("abc");
  return 0;
}
```

```sh
e-acsl-gcc -q -c -o direct.inst.c -O direct direct.c
for i in 0 1 2 3; do ./direct.e-acsl $i; echo "exit $?"; done
```

Expected: all four exit 0. Actual: 0 (local array) and 1 (writable global array) pass; 2 (`const`
array) and 3 (string literal) pass the `\valid_read` on line 5, then abort on line 6:

```text
direct.c: In function 'check'
direct.c:6: Error: Assertion failed:
	The failing predicate is:
	\object_pointer(p).
	With values at failure point:
	- \object_pointer(p): 0
	- sizeof(char const): 1
	- p: 0x559763fad0a6
Aborted (core dumped)
exit 134
```

The `-warn-invalid-pointer` form, the case met in practice (`five.c`):

```c
#include <stdio.h>

static const unsigned char const_table[4] = {1, 2, 3, 0};
static unsigned char plain_table[4] = {1, 2, 3, 0};

static int scan(const unsigned char *p) {
  int n = 0;
  while (*p) {
    unsigned char v = *p++;
    n += v;
  }
  return n;
}

int main(int argc, char **argv) {
  unsigned char local[4] = {1, 2, 3, 0};
  int which = argc > 1 ? argv[1][0] - '0' : 0;
  if (which == 0) fprintf(stderr, "local array: done %d\n", scan(local));
  if (which == 1) fprintf(stderr, "plain global array: done %d\n", scan(plain_table));
  if (which == 2) fprintf(stderr, "static const array: done %d\n", scan(const_table));
  if (which == 3) fprintf(stderr, "string literal: done %d\n", scan((const unsigned char *)"abc"));
  return 0;
}
```

```sh
e-acsl-gcc -q -c -F "-rte -warn-invalid-pointer" -o five.inst.c -O five five.c
```

Objects 0 and 1 print `done 6`; 2 and 3 abort with exit 134 at the first read:

```text
five.c: In function 'scan'
five.c:8: Error: E-ACSL RTE failed:
	The failing predicate is:
	invalid pointer:
		\null ≡ p ∨ \object_pointer(p).
	With values at failure point:
	- \object_pointer(p): 0
	- sizeof(unsigned char const): 1
	- p: 0x64f6fe16f924
Aborted (core dumped)
```

Both programs were built in every combination below, on 34.0~beta and on `master`, with the same
result in every cell: objects 0 and 1 pass, 2 and 3 fail.

| Back end | `-e-acsl-full-mtracking` (`-M`) | `direct.c` | `five.c` with `-rte -warn-invalid-pointer` |
| :-- | :-- | :-- | :-- |
| gcc | no | 2, 3 fail | 2, 3 fail |
| gcc | yes | 2, 3 fail | 2, 3 fail |
| clang (`-G clang`) | no | 2, 3 fail | 2, 3 fail |
| clang (`-G clang`) | yes | 2, 3 fail | 2, 3 fail |

All of these use the default segment memory model. With `-m bittree` the four cases of `direct.c`
pass, but only because, in that build, `\valid(p)` is also true for the `const` array and the literal
(see "Also seen" below).

## Cause

`plugins/e-acsl/share/e-acsl/observation_model/e_acsl_observation_model.c:103-107` (same lines in
34.0-beta and `3dff90fc70`):

```c
int eacsl_object_pointer(void *ptr, size_t size, void *ptr_base,
                         void *addrof_base) {
  return eacsl_valid(ptr, size, ptr_base, addrof_base)
         || eacsl_valid(ptr - size, size, ptr_base, addrof_base);
}
```

`eacsl_valid` is the implementation of `\valid`, which requires writability. In the segment model
(`segment_model/e_acsl_segment_observation_model.c:138-155`):

```c
  int result = allocated((uintptr_t)ptr, size, (uintptr_t)ptr_base)
               && !readonly(ptr)
```

and in the bittree model (`bittree_model/e_acsl_bittree_observation_model.c:242`)
`blk != NULL && !blk->is_readonly`. `eacsl_valid_read`, a few lines further in both files, is the same
test without the read-only condition.

E-ACSL marks string literals and `const` globals read-only at start-up
(`__e_acsl_mark_readonly((void *)(const_table))` and `(void *)(__fc_lit_string1)` in
`__e_acsl_globals_init`), so for them `eacsl_valid` is 0 at both `ptr` and `ptr - size`, and
`eacsl_object_pointer` returns 0.

The translation itself is fine: `Rte_analysis.pointer_value` (`src/analyses/rte_analysis.ml:317-339`)
builds `\null == t || \object_pointer(t)`, and `Memory_translate.call_valid`
(`src/code_generator/memory_translate.ml:570-599`) passes `ptr`, `sizeof(*ptr)`, the base and its
address to `__e_acsl_object_pointer`, as it does for `\valid` and `\valid_read`.

The ACSL contract of the builtin, `e_acsl_observation_model.h:325-354`, is written with `\valid` too
(behaviours `valid` and `minus_one`), so it states the same writability requirement and would need the
same change.

No test covers the case. `plugins/e-acsl/tests/memory/objects.c` checks `\object_pointer` on local
scalars, a local array, local structs and their members, and a dangling pointer, all writable.
`tests/acsl-rte/rte.c` runs with `-warn-invalid-pointer` but has no string literal or `const` object.

## Proposed fix

Use `eacsl_valid_read` in `eacsl_object_pointer`, and `\valid_read` in its contract:

```diff
 int eacsl_object_pointer(void *ptr, size_t size, void *ptr_base,
                          void *addrof_base) {
-  return eacsl_valid(ptr, size, ptr_base, addrof_base)
-         || eacsl_valid(ptr - size, size, ptr_base, addrof_base);
+  return eacsl_valid_read(ptr, size, ptr_base, addrof_base)
+         || eacsl_valid_read(ptr - size, size, ptr_base, addrof_base);
 }
```

What was checked: the runtime is compiled from `share/e-acsl` at every `e-acsl-gcc` build, so I
copied that directory inside a throwaway 34.0~beta container, applied the two-line change to the copy
and built with `e-acsl-gcc --e-acsl-share=<copy>`:

- `direct.c` and `five.c`: all four objects pass in all eight cells of the table above;
  `five.c` 3 prints `done 294` (`'a' + 'b' + 'c'`).
- Negative cases still behave, with gcc and clang, with and without `-M`
  (`t = const_table`, `s = "abc"`): `\object_pointer(t + 4)` and `\object_pointer(s + 4)` (one past the
  end) hold; `!\valid(t)`, `!\object_pointer(t + 5)`, `!\object_pointer(s + 5)` and
  `!\object_pointer(t - 1)` hold. With the stock runtime the same program aborts on
  `\object_pointer(t + 4)`.

### Patch proposed (2026-11-16)

[`./patches/29-eacsl-object-pointer-readonly-static.patch`](./patches/29-eacsl-object-pointer-readonly-static.patch),
one commit on `3dff90fc70`, "[e-acsl] \object_pointer does not require the object to be writable":

- `e_acsl_observation_model.c`: the two-line change above.
- `e_acsl_observation_model.h`: `\valid_read` instead of `\valid` in the behaviours `valid`, `minus_one`
  and `invalid_pointer_ptr` of the contract of `eacsl_object_pointer` (`separated_ptr` has no validity
  clause), plus a doc comment like those of the neighbouring builtins. The contract matters: in the
  default configuration of the test suite Eva analyses the instrumented code, and with the old contract
  it concludes that `\object_pointer` is false on a `const` array (see "Validation").
- New test `tests/memory/object_pointer_readonly.c` (not an edit of `tests/memory/objects.c`, whose
  oracle open MR !31 rewrites), with `check` annotations so that one run reports every failing case:
  for a `static const` array `t` and a string literal `s`, `\valid_read(p) && !\valid(p)` (the block is
  still read-only), `\object_pointer` at `t`, `t + 3`, `t + 4` (one past the end), `s`, `s + 4`, and
  `!\object_pointer` at `t + 5`, `t - 1`, `s + 5`, `s - 1`; and `\object_pointer(stdin)`. Oracles:
  `oracle/gen_object_pointer_readonly.0.c` (677 lines) and `oracle/object_pointer_readonly.0.res.oracle`.
  No `dev` oracle file: the run-time error log is empty, like the other `memory/` tests.
- No function formal in the test, so it does not depend on !28 (Issue 13).

What else depends on `eacsl_object_pointer`, checked in the source: nothing else in the runtime calls
it; `--temporal` is unaffected (`eacsl_valid_read` has the same `temporal_valid` check as
`eacsl_valid`, in both models); `-e-acsl-full-mtracking` changes what is tracked, not the predicate.
The E-ACSL reference manual (`doc/refman/memory.tex`) only gives the grammar of `\object_pointer`, and
the user manual does not describe it. The generated code is unchanged (the new test's `gen_*.c` is the
same before and after), and no existing oracle changes. The suites whose generated code calls
`__e_acsl_object_pointer` are `memory/objects.c`, `acsl-rte/rte.c` and `trivial_rte.i`, `libc/mem.c`
and `temporal/t_memcpy.c`; all were rerun (see "Validation").

Not in the regression test: a `-warn-invalid-pointer` case. Enabling the option on this test file would
put an `invalid pointer` guard on the terms `t + 5`, `t - 1` and `s + 5` themselves (E-ACSL's RTE
analysis guards every `PlusPI` term), so the negative cases would abort by design. The guard calls the
same runtime function; the `-warn-invalid-pointer` case is in the reproducer (`-rte.c`).

## Also seen, not investigated

With `-m bittree` (34.0~beta), `//@ assert \valid(t);` holds for `t = const_table` and for a string
literal, and `//@ assert !\valid(t);` aborts, although the instrumented code calls
`__e_acsl_mark_readonly` on both right after `__e_acsl_store_block` and `__e_acsl_full_init`. The
same bittree build does catch `\object_pointer(t + 5)` and `\valid(t + 5)`, so checks are on. In that
model the read-only marking does not take effect, and `\object_pointer` passes there only for that
reason. The segment model gets `!\valid(t)` right. Why bittree loses the mark was not looked into:
`eacsl_mark_readonly` in `bittree_model/e_acsl_bittree_observation_model.c:145-153` looks the block up
with `bt_lookup` and sets `is_readonly`, which `eacsl_valid` tests; the cause is not visible from the
source alone.

Also with `-m bittree` (seen 2026-11-16, master and 34.0~beta): `stdin`, `stdout`, `stderr` and `errno`
are not tracked at all. `\object_pointer(stderr)` is 0, so with `-rte -warn-invalid-pointer` every
`fprintf(stderr, ...)` in `five.c` aborts in that model, for all four objects. Cause, from the source:
the bittree `eacsl_memory_init` (`bittree_model/e_acsl_bittree_observation_model.c:581-593`) has a
comment "Tracking safe locations" but never calls `collect_safe_locations()`; the segment model calls it
(`segment_model/e_acsl_shadow_concurrency.c:175`). This is a separate bug, not filed; the reproducer's
`-rte.c` avoids `<stdio.h>` for that reason. The new test's `stdin` check and its two `!\valid` checks
fail with `-m bittree` before and after the patch, for these two reasons; the test suite runs the
segment model.

## Validation

`master` at `3dff90fc70` in `framac-master-audit:3dff90f`, then the same tree with the patch, rebuilt
with `dune build @install --release -j 8` and installed (Debian 13, gcc 14.2.0, clang 19.1.7). The
patched container is saved as `framac-master-audit:3dff90f-p29`.

The "before" column is `master`; the reproducer rows and the hand-built test rows were also run on
34.0~beta (`framac-analysis:fc34`), with the same results. ptests, lint and `git am` ran on `master` only.

| Check | `master` | Patched |
|---|---|---|
| Reproducer `29-...static.c`, objects 0-3 | 0 0 134 134 (`\object_pointer(p)`, line 6) | 0 0 0 0 |
| Reproducer `29-...static-rte.c`, `-F "-rte -warn-invalid-pointer"`, objects 0-3 | 0 0 134 134 (`invalid pointer`, line 6) | 0 0 0 0 |
| Both, with `-M`, `-G clang`, `-G clang -M`, `--temporal` | 0 0 134 134 | 0 0 0 0 |
| Both, with `-m bittree` | 0 0 0 0 (read-only mark lost, see "Also seen") | 0 0 0 0 |
| New test, `dev` configuration (compiled and run) | `T0`, `T3`, `T4`, `S0`, `S4`, `IN` fail; error log differs from the empty oracle | passes |
| New test, default configuration (Eva on the instrumented code) | `non_blocking: precondition got status invalid` on lines 15, 16, 17, 23, 24 (from the old contract) | passes against the promoted oracle |
| New test built by hand with `-M`, `-G clang`, `-G clang -M`, `--temporal` | `T0 T3 T4 S0 S4 IN` fail, the rest hold | every check holds |
| Same, `-m bittree` | `RO_T RO_S IN` fail | `RO_T RO_S IN` fail (out of scope, "Also seen") |
| `frama-c -eva` on `direct.c` | both assertions of `check` valid | not rerun (kernel and Eva unchanged) |
| ptests, default configuration, all of `plugins/e-acsl/tests` (198 results, all regenerated after the patched install) | — | only the new test's two oracles differ (promoted); every other test matches |
| ptests, `dev` configuration of `memory/`, `acsl-rte/`, `temporal/`, `libc/` | — | all match (`objects.c`, `rte.c`, `t_memcpy.c`, `mem.c` call `__e_acsl_object_pointer`) |
| `./dev/check-files.sh -p HEAD~1` in `framac-lint:3dff90f`, user `opam` | — | passes ("Lint 5 file(s)") |
| `git am --keep-non-patch` on pristine `3dff90fc70` | — | applies; tree identical to the commit |
| `git am --3way --keep-non-patch` after the 22 existing patches (12 before 10) | — | applies, no conflict |

Not run: the `dev` configuration of the suites whose generated code does not call
`__e_acsl_object_pointer` (`arith/`, `bts/`, `builtin/`, `concurrency/`, `constructs/`, `examples/`,
`format/`, `full-mtracking/`, `inductive/`, `special/`); the change is confined to that function and
its contract. Not run either: ptests on the stacked tree (the 22 patches plus this one).

## Workaround

None in the pipeline: it does not pass `-warn-invalid-pointer` to E-ACSL, so Eva's `pointer_value`
alarms get no run-time check in Phase 1. See
[`../../troubleshooting/eacsl-and-fuzzing.md`](../../troubleshooting/eacsl-and-fuzzing.md), entry
"With `-warn-invalid-pointer`, Almost Every Input Fails an E-ACSL Build ...". Shipping a patched copy
of the runtime through `e-acsl-gcc --e-acsl-share` would work, as the check above shows, but it was not
adopted.

## Tracker

Searched on 2026-11-16 with the authenticated API of git.frama-c.com (`pub/frama-c`, issues and merge
requests, all states) for `object_pointer`, `warn-invalid-pointer`, `invalid pointer`,
`pointer_value`, `readonly`, `read-only` and `string literal`, and the 2026-11-09 export
([`./pub-frama-c_work_items_2026-11-09.csv`](./pub-frama-c_work_items_2026-11-09.csv)). No duplicate.

- The hits are this folder's own reports (#2794, #2795, !26 and others that only mention these words)
  or unrelated older issues.
- #1131 ("E-ACSL reports use of invalid pointer while in fact the pointer is valid", 2013, closed) is
  about `\valid` on a writable global, before `\object_pointer` existed.
- #2122 (2011, closed) is about Eva and wide string literals.
- The private E-ACSL tracker (`frama-c/e-acsl`) cannot be read from this account.
