# E-ACSL: an unbounded range anywhere aborts the whole run (`-L` and `strtok_r`, `getsockopt`, `wcschr`), instead of ignoring the annotation

**Filed upstream on 2026-11-15:** issue [#2798](https://git.frama-c.com/pub/frama-c/-/work_items/2798), merge request [!29](https://git.frama-c.com/pub/frama-c/-/merge_requests/29).

Draft bug report for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).

**Filing package:** [issue](./filing/04-eacsl-unbounded-range-abort-issue.md), [MR](./filing/04-eacsl-unbounded-range-abort-mr.md), [reproducer](./repro/04-eacsl-unbounded-range-abort.sh), [patch](./patches/04-eacsl-unbounded-range-abort.patch)

## Summary

E-ACSL does not support unbounded ranges (`p + (0..)`). That is fair: there is nothing to check at
runtime. But in four places it reacts to one with `Options.abort`:

```ocaml
| Trange(None, _) | Trange(_, None) ->
  Options.abort ~current:true "unbounded ranges are not part of E-ACSl"
```

`Options.abort` stops the whole run. It does not drop the annotation: the program is not
instrumented at all. Every other construct E-ACSL cannot translate goes through
`Error.not_yet` / `Error.untypable`, which drops just that annotation with an
`Ignoring annotation.` warning and goes on.

The abort is also reached for contracts the user did not write. Frama-C's own libc uses unbounded
ranges outside `assigns` clauses in six contracts on `master` (`3dff90fc70`):

| Function | Contract (`share/libc/…`) | `e-acsl-gcc -L` on a caller, `master` |
|---|---|---|
| `strtok_r` | `string.h:354-355`: `requires separation: \separated(…, *saveptr+(0..));` | aborted (`string.h:352`) |
| `getsockopt` | `sys/socket.h:397-398`: `requires optval_null_or_valid: optval == \null \|\| \valid(((char*)optval)+(0..));` | aborted (`sys/socket.h:377`) |
| `wcschr` | `wchar.h:109-110`: `ensures result_null_or_inside_wcs: \result == \null \|\| \subset(\result, wcs+(0..));` | aborted (`wchar.h:106`) |
| `wcspbrk` | `wchar.h:200-201`: same `ensures` on `wcs+(0 .. )` | aborted (`wchar.h:196`) |
| `wcsrchr` | `wchar.h:208-209`: same `ensures` on `wcs+(0 .. )` | aborted (`wchar.h:205`) |
| `wcsstr` | `wchar.h:225-226`: `ensures result_null_or_inside_haystack: … \subset (\result, haystack+(0 .. ));` | aborted (`wchar.h:221`) |

With `e-acsl-gcc -L` (`--frama-c-stdlib`), E-ACSL instruments the libc contracts of the functions
the program calls. A program that calls any of these functions therefore cannot be instrumented at
all. (The `-L` runs used `-e -D_DEFAULT_SOURCE` so that the compiler sees the POSIX prototypes;
that is a separate `e-acsl-gcc` issue.)

The `getsockopt` contract is wrong in its own right (it is unsatisfiable); that is reported
separately in [frama-c-getsockopt-unbounded-range.md](./frama-c-getsockopt-unbounded-range.md). Fixing
it would not fix this issue, which concerns E-ACSL's handling of every unbounded range.

## Versions

- Reproduced on `master` at `3dff90fc70` (2026-11-13, `35.0~~dev (Bromine)`), Debian 13,
  gcc 14.2.0, with [`./repro/04-eacsl-unbounded-range-abort.sh`](./repro/04-eacsl-unbounded-range-abort.sh)
  (2026-11-15). First reproduced on `ad24dca` (2026-11-02), with gcc and clang 19.1.7.
- Same output on `34.0~beta (Selenium)` (2026-11-15).
- The E-ACSL interval changes merged since `ad24dca` (`67e5edb4a4`, `8768bcbeb7`, `cc5b8431a2`,
  `4265ab3bb5`) only touch the join and meet of semi-bounded intervals in `interval_utils.ml`. The
  four abort sites are unchanged on `3dff90fc70`, and the patch below is the same.

## Reproduction

`s.c`:

```c
#include <string.h>
int main(void) {
  char buf[] = "a:b";
  char *save = 0;
  char *tok = strtok_r(buf, ":", &save);
  return tok != 0;
}
```

```text
$ e-acsl-gcc -L -o s.instrumented.c -O s s.c
e-acsl-gcc: fatal error: aborted by Frama-C
...
[e-acsl] FRAMAC_SHARE/libc/string.h:352: User Error:
  unbounded ranges are not part of E-ACSl
[kernel] Plug-in e-acsl aborted: invalid user input.
```

The same program with `strchr` instead of `strtok_r` builds and runs. A user annotation has the
same effect. `unb_user.c`:

```c
/*@ requires \valid_read(p + (0..)); requires n >= 0; */
int first(const char *p, int n) { return n > 0 ? p[0] : 0; }
int main(void) { char b[2] = "a"; return first(b, -1); }
```

```text
$ e-acsl-gcc -o unb.c -O unb unb_user.c
[e-acsl] unb_user.c:3: User Error: unbounded ranges are not part of E-ACSl
[kernel] Plug-in e-acsl aborted: invalid user input.
e-acsl-gcc: fatal error: aborted by Frama-C
```

The valid `requires n >= 0` clause is lost along with the rest of the program.

## Fix

Patch: [`./patches/04-eacsl-unbounded-range-abort.patch`](./patches/04-eacsl-unbounded-range-abort.patch),
one commit on `fix/e-acsl-unbounded-range` from `3dff90fc70`, "[e-acsl] ignore annotations with
unbounded ranges instead of aborting". It treats an unbounded range as untypable, like the other
unsupported constructs: the annotation that contains it is dropped with a warning, and the rest of
the program is still instrumented. It adds the regression test
`plugins/e-acsl/tests/memory/unbounded_range.c` (a `requires` and two `assert`s with unbounded
ranges next to checkable clauses) with its default-configuration oracles. All four sites are the
same one-line change:

```diff
--- a/plugins/e-acsl/src/analyses/interval.ml
+++ b/plugins/e-acsl/src/analyses/interval.ml
@@ -517,7 +517,7 @@ let rec infer ~force ~logic_env t =
       let i2 = recurse n2 in
       Error.map2 join i1 i2
     | Trange(None, _) | Trange(_, None) ->
-      Options.abort ~current:true "unbounded ranges are not part of E-ACSl"
+      Error.untypable "unbounded range"
 
     | Tlet (li,t) ->
       let li_t = Terms.of_li li in
--- a/plugins/e-acsl/src/analyses/memory_tracking.ml
+++ b/plugins/e-acsl/src/analyses/memory_tracking.ml
@@ -387,7 +387,7 @@ module rec Transfer
       let varinfos = register_term kf varinfos t1 in
       register_term kf varinfos t2
     | Trange(None, _) | Trange(_, None) ->
-      Options.abort "unbounded ranges are not part of E-ACSL"
+      Error.untypable "unbounded range"
 
   and register_body kf varinfos = function
     | LBnone | LBreads _ -> varinfos
--- a/plugins/e-acsl/src/analyses/typing.ml
+++ b/plugins/e-acsl/src/analyses/typing.ml
@@ -663,7 +663,7 @@ let rec type_term
     | Tcomprehension (_,_,_) -> Error.not_yet "tset comprehension"
 
     | Trange(None, _) | Trange(_, None) ->
-      Options.abort ~current:true "unbounded ranges are not part of E-ACSl"
+      Error.untypable "unbounded range"
     | Trange(Some n1, Some n2) ->
       ignore (type_term ~use_gmp_opt ~profile n1);
       ignore (type_term ~use_gmp_opt ~profile n2);
--- a/plugins/e-acsl/src/code_generator/memory_translate.ml
+++ b/plugins/e-acsl/src/code_generator/memory_translate.ml
@@ -177,7 +177,7 @@ let range_to_ptr_and_size ~adata ~loc kf env ptr r p =
     | Trange(Some n1, Some n2) ->
       n1, n2
     | Trange(None, _) | Trange(_, None) ->
-      Options.abort ~current:true "unbounded ranges are not part of E-ACSL"
+      Error.untypable "unbounded range"
     | _ ->
       assert false
   in
```

`untypable` rather than `not_yet`: E-ACSL cannot check an unbounded range at runtime, so this is a
limit of the language subset, not a missing feature. That matches what the current message says.
All four sites get the same change, so whichever phase meets the range first drops the annotation.

The patch also fixes the "E-ACSl" typo in two of the messages.

## Validation of the fix

Built on `3dff90fc70` with the patch (image `framac-master-audit:3dff90f`, incremental
`dune build @install --release` and `dune install`), 2026-11-15:

| Check | `master` `3dff90fc70` | 34.0~beta | Patched |
|---|---|---|---|
| `e-acsl-gcc unb_user.c` | `unbounded ranges are not part of E-ACSl`, aborted | same | `invalid E-ACSL construct 'unbounded range'. Ignoring annotation.`; builds; `requires n >= 0` is still checked and fails at runtime as it should |
| `e-acsl-gcc -L -e -D_DEFAULT_SOURCE` on a `strtok_r` caller | aborted (`string.h:352`) | same | builds; runs, exit 0 |
| same on a `getsockopt` caller | aborted (`sys/socket.h:377`) | not run | warning on `socket.h:398`; builds; runs, exit 0 |
| same on a `wcschr` caller | aborted (`wchar.h:106`) | not run | builds; runs, exit 0 |
| same on `wcspbrk`, `wcsrchr`, `wcsstr` callers | aborted (`wchar.h:196`, `:205`, `:221`) | not run | builds; runs, exit 1 (the value the program returns) |
| ptests `plugins/e-acsl/tests`, default configuration (198 results) | new test aborts | — | only the two new oracles; promoted; rerun clean |
| ptests `plugins/e-acsl/tests`, `dev` configuration (compile and run) | existing tests pass; new test fails | — | pass, new test included |
| `make check-lint` (7 changed files, ocp-indent 1.10.0) | — | — | clean (`clang-format` not installed: new C test not checked) |

Earlier validation on `ad24dca` (2026-11-02) gave the same results, plus: a `strchr` control builds
with and without the patch.

## Workaround

Do not use `-L` for programs that call `strtok_r`, `getsockopt`, `wcschr`, `wcspbrk`, `wcsrchr`
or `wcsstr`. With the host libc
(the default), libc contracts are not instrumented. Alternatively, override the contract with a
bounded one in a project-local header.
