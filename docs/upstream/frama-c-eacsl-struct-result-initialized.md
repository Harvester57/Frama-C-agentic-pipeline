# E-ACSL: false `\initialized(&\result.a)` failure in the postcondition of every function returning a struct, when initialization checks are on

Draft bug report for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).

**Same family as
[frama-c-eacsl-formal-params-initialized.md](frama-c-eacsl-formal-params-initialized.md)**: there the
formals are registered in shadow memory but never marked initialized, here the wrapper's `__retres`
is. File the two together. The two patches apply cleanly together and were tested together.

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

- Reproduced with Frama-C `35.0~~dev (Bromine)`, built from `master` at `ad24dca` (2026-11-02),
  Debian 13, gcc 14.2.0, clang 19.1.7.
- Same behaviour in `34.0~~dev (Selenium)`.

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
$ e-acsl-gcc -F "-rte -rte-initialized" -o si.c -O sb struct_repro.c && ./sb.e-acsl
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

## Proposed fix

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

### Alternative

Emit `__e_acsl_full_init((void *)(& __retres));` after `__retres = f(...);` in the generated
wrapper, like every other tracked struct assignment. The `\initialized` guard then stays and
passes. That fixes the runtime state rather than skipping the check, but it touches the wrapper
generator. I have not implemented or tested it.

## Validation of the proposed fix

Built from `ad24dca` with the patch:

| Check | `master` | Patched |
|---|---|---|
| `struct_repro.c`, `-F "-e-acsl-rte 2"` | false `\initialized(&\result.a)`, abort | builds; runs, exit 0 |
| `scalar_repro.c` (`ensures \result >= 0;`), `-F "-e-acsl-rte 2"` | runs, exit 0 | runs, exit 0 |
| `struct_repro.c`, `-M -F "-rte -rte-initialized @all"` | false `\initialized(&\result.a)`, abort | builds; runs, exit 0 |
| `partial_struct.c` (two fields), `-F "-e-acsl-rte 2"` | false `\initialized(&\result.a)`, abort | builds; runs, exit 0 |
| `uninit_neg.c` (a genuinely uninitialized local, `int x; /*@ assert x == 0; */`), `-F "-e-acsl-rte 2"` | reported | still reported (`E-ACSL RTE failed … uninitialized`) |
| ptests `plugins/e-acsl/tests` (default and `dev` configurations) | — | no change |

## Workaround

Turn off initialization checks on functions that return a struct and have field-level `ensures`
clauses. Alternatively, write the postcondition on a caller-side variable instead of `\result`.
