# E-ACSL: false `\initialized(&\result.a)` failure in the postcondition of every function returning a struct, when initialization checks are on

**Filed upstream on 2026-11-15:** issue [#2801](https://git.frama-c.com/pub/frama-c/-/work_items/2801), merge request [!32](https://git.frama-c.com/pub/frama-c/-/merge_requests/32).

Draft bug report for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).

**Filing package:** [issue](./filing/08-eacsl-struct-result-initialized-issue.md), [MR](./filing/08-eacsl-struct-result-initialized-mr.md), [reproducer](./repro/08-eacsl-struct-result-initialized.sh), [patch](./patches/08-eacsl-struct-result-initialized.patch)

**Same family as
[frama-c-eacsl-formal-params-initialized.md](./frama-c-eacsl-formal-params-initialized.md)**: there the
formals are registered in shadow memory but never marked initialized, here the wrapper's `__retres`
is. File the two together, as separate issues and MRs. Each patch applies alone on `3dff90fc70`;
they also apply together, and were tested together (reproducers, negative controls, and the E-ACSL
ptests in both configurations).

## Summary

When initialization checks are enabled (`-e-acsl-rte 2` or higher, `-e-acsl-rte-initialized`, or
`-rte -rte-initialized`), an `ensures` clause that reads a field of a struct `\result` always fails
at runtime, even though the function returns a fully initialized struct:

```text
struct_repro.c: In function 'make_s'
struct_repro.c:4: Error: E-ACSL RTE failed:
	The failing predicate is:
	uninitialized:
		\initialized(&\result.a).
	With values at failure point:
	- uninitialized: \initialized(&\result.a): 0
	- sizeof(int): 4
	- &\result.a: 0x7ffd779e550c
Aborted
```

This is a false positive on correct code. Being blocking, it aborts the program at the first call,
so nothing after it is checked. Under a fuzzer, every input that reaches the function "crashes".

### Cause

The generated wrapper holds the result in a local, `__retres`, and registers it with the runtime but
never marks it initialized:

```c
struct S __gen_e_acsl_make_s(int x)
{
  struct S __retres;
  __e_acsl_store_block((void *)(& __retres),4UL);
  ...
  __retres = make_s(x);          /* no __e_acsl_full_init(&__retres) */
  ...
  __gen_e_acsl_initialized = __e_acsl_initialized((void *)(& __retres.a), sizeof(int));
```

The same struct copy anywhere else is followed by `__e_acsl_full_init`. For example, `main` gets
`struct S s = __gen_e_acsl_make_s(0); __e_acsl_store_block(&s, 4); __e_acsl_full_init(&s);`.

`needs_guard` in `rte_analysis.ml:492-505` already handles this for scalar results:

```ocaml
(* Frama-C kernel ensures that '__retres' is always initialized. *)
| TResult _, TNoOffset -> false
| _ -> not Ast_types.C.(is_fun typ || is_struct_or_union typ)
```

The `TNoOffset` restriction means `\result.a` (a `TResult` with a field offset) falls into the last
case. The field is an `int`, so a guard is added. `scalar_repro.c`, with `ensures \result >= 0;`,
does not fail.

## Versions

- Reproduced on `master` at `3dff90fc70` (2026-11-13, `35.0~~dev (Bromine)`), Debian 13,
  gcc 14.2.0, with [`./repro/08-eacsl-struct-result-initialized.sh`](./repro/08-eacsl-struct-result-initialized.sh)
  (2026-11-15). First reproduced on `ad24dca` (2026-11-02), with gcc and clang 19.1.7.
- Same output on `34.0~beta (Selenium)` (2026-11-15).

## Reproduction

`struct_repro.c`:

```c
struct S { int a; };

/*@ requires x >= 0;
    ensures \result.a == x; */
struct S make_s(int x) {
  struct S s = { x };
  return s;
}

int main(void) {
  struct S s = make_s(0);
  return s.a;
}
```

```text
$ e-acsl-gcc -F "-rte -rte-initialized @all" -o si.c -O sb struct_repro.c && ./sb.e-acsl
struct_repro.c: In function 'make_s'
struct_repro.c:4: Error: E-ACSL RTE failed:
	The failing predicate is:
	uninitialized:
		\initialized(&\result.a).
...
Aborted
```

The same failure occurs with `-F "-e-acsl-rte 2"`, and with `-M -F "-rte -rte-initialized @all"`
(full memory tracking). It also occurs with two-field structs
(`ensures \result.a == x && \result.b == x + 1;`). Without initialization checks (plain
`e-acsl-gcc`, or `-M` alone), the program runs and exits 0.

## Fix

Patch: [`./patches/08-eacsl-struct-result-initialized.patch`](./patches/08-eacsl-struct-result-initialized.patch),
one commit on `fix/e-acsl-struct-result-initialized` from `3dff90fc70`, "[e-acsl] no
initialization guard on the fields of \result". It adds the regression test
`plugins/e-acsl/tests/acsl-rte/struct_result.c` (`STDOPT: #"-e-acsl-rte-initialized"`, a two-field
struct with `ensures \result.a == x && \result.b == x + 1`) with its default-configuration oracles.

Extend the existing `__retres` exemption to its fields:

```diff
--- a/plugins/e-acsl/src/analyses/rte_analysis.ml
+++ b/plugins/e-acsl/src/analyses/rte_analysis.ml
@@ -496,8 +496,9 @@ let rte_visitor =
         | TVar { lv_origin = Some vi }, TNoOffset ->
           not (vi.vglob || vi.vformal || vi.vtemp) &&
           not (Ast_types.C.is_struct_or_union typ)
-        (* Frama-C kernel ensures that '__retres' is always initialized. *)
-        | TResult _, TNoOffset -> false
+        (* Frama-C kernel ensures that '__retres' is always initialized,
+           and so are its fields. *)
+        | TResult _, _ -> false
         | _ -> not Ast_types.C.(is_fun typ || is_struct_or_union typ)
       in
       if Flags.needs_initialized self#current_kf && needs_guard lv then
```

This matches what E-ACSL already does for any other struct copy, which it marks fully initialized
(`__e_acsl_full_init`). No check is lost compared with a struct returned into a caller's variable.
A user cannot write `\initialized(&\result.a)` (the kernel rejects it: `not an addressable left
value: \result.a`), so the guard was the only reader of the shadow memory of `__retres`.

Cost: a field of the returned struct that the function left uninitialized is no longer reported
when the postcondition reads it. Checked on `3dff90fc70`: with a function that sets only `.a`, the
postcondition on `\result.b` now compares the garbage value instead of failing on initialization.
Today that check fails on correct functions too, so it could not tell the two cases apart.

### Alternative

Emit `__e_acsl_full_init((void *)(& __retres));` after `__retres = f(...);` in the generated
wrapper, like every other tracked struct assignment. The `\initialized` guard then stays and
passes. That fixes the runtime state rather than skipping the check, but it touches the wrapper
generator, and it has the same cost (a field left uninitialized by the callee is then marked
initialized too). I have not implemented or tested it.

## Validation of the fix

Built on `3dff90fc70` with the patch (image `framac-master-audit:3dff90f`, incremental
`dune build @install --release` and `dune install`), 2026-11-15:

| Check | `master` `3dff90fc70` | 34.0~beta | Patched |
|---|---|---|---|
| `struct_repro.c`, plain `e-acsl-gcc` | runs, exit 0 | same | runs, exit 0 |
| `struct_repro.c`, `-F "-rte -rte-initialized @all"` | false `\initialized(&\result.a)`, abort | same | builds; runs, exit 0 |
| `struct_repro.c`, `-F -e-acsl-rte-initialized` | false `\initialized(&\result.a)`, abort | not run | builds; runs, exit 0 |
| scalar result (`ensures \result >= 0;`) with initialization checks | runs, exit 0 | not run | runs, exit 0 |
| a genuinely uninitialized local (`int y; /*@ assert y == 0; */`) with initialization checks | reported | not run | still reported |
| ptests `plugins/e-acsl/tests`, default configuration (198 results) | — | — | only the two new oracles; promoted; rerun clean |
| ptests `plugins/e-acsl/tests`, `dev` configuration (compile and run) | new test fails on the postcondition | — | pass, new test included |
| With the formal-parameter patch also applied: E-ACSL ptests, default and `dev` | — | — | pass with the oracles of both patches, no difference |
| `make check-lint` (4 changed files, ocp-indent 1.10.0) | — | — | clean (`clang-format` not installed: new C test not checked) |

Earlier validation on `ad24dca` (2026-11-02) gave the same results, plus: `-F "-e-acsl-rte 2"` and
`-M -F "-rte -rte-initialized @all"` (full memory tracking) fail on `master` and pass patched.

## Workaround

Turn off initialization checks on functions that return a struct and have field-level `ensures`
clauses. Alternatively, write the postcondition on a caller-side variable instead of `\result`.
