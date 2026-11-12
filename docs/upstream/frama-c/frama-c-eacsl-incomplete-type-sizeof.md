# E-ACSL: annotations on pointers to incomplete (opaque) struct types produce `sizeof`/`alignof` of the incomplete type, so the instrumented code does not compile

Draft bug report for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).

## Summary

Opaque handles are common in C APIs: `typedef struct json_object json_object;` in a public header,
with the struct defined only in the library. When E-ACSL translates an annotation on such a pointer,
it emits `sizeof(json_object)` or `__alignof__(json_object)` into the instrumented code. Neither
compiles, so `e-acsl-gcc` stops with `fail to compile/link instrumented code`. Three common
annotations trigger it:

| Annotation | Where it comes from | Generated C |
|---|---|---|
| `\aligned(p, alignof(json_object))` | RTE `pointer_alignment` on the cast `(json_object *)p` | `__alignof__(json_object)` |
| `\valid_read(obj)` / `\valid(obj)` | user contract on an opaque handle | `sizeof(json_object const)` |
| `\initialized(obj)` | user contract on an opaque handle | `sizeof(json_object const)` |

E-ACSL already knows this case. For its own alignment guards it checks completeness and warns
instead (`rte_analysis.ml:515` and `:566`):

```text
[e-acsl] opaque_valid.c:3: Warning:
  cannot create the pointer alignment guard of obj because json_object const is an incomplete type
```

The terms that come from RTE or from the user, and the memory built-ins (`Smart_exp.ptr_sizeof` in
`memory_translate.ml:281`, `TSizeOf ty` in `range_to_ptr_and_size`), have no such check.

## Versions

- Reproduced with Frama-C `35.0~~dev (Bromine)`, built from `master` at `ad24dca` (2026-11-02),
  Debian 13, gcc 14.2.0 and clang 19.1.7 (both reject the generated code).
- Same behaviour in `34.0~~dev (Selenium)`.

## Reproduction

`opaque_cast.c` (RTE annotation):

```c
typedef struct json_object json_object;

json_object *from_void(void *p) {
  return (json_object *)p;
}

int main(void) {
  return from_void(0) != 0;
}
```

```text
$ frama-c -rte opaque_cast.c -print | grep alignment
  /*@ assert rte: pointer_alignment: \aligned(p,alignof(json_object)); */

$ e-acsl-gcc -F -rte -o oc.inst.c -O oc opaque_cast.c
oc.inst.c:322:56: error: invalid application of ‘__alignof__’ to incomplete type ‘json_object’
oc.inst.c:325:45: error: invalid application of ‘__alignof__’ to incomplete type ‘json_object’
e-acsl-gcc: fatal error: fail to compile/link instrumented code
```

`opaque_valid.c` (user contract):

```c
typedef struct json_object json_object;

/*@ requires obj == \null || \valid_read(obj); */
int is_set(const json_object *obj) {
  return obj != 0;
}

int main(void) {
  return is_set(0);
}
```

```text
$ e-acsl-gcc -o ov.inst.c -O ov opaque_valid.c
[e-acsl] opaque_valid.c:3: Warning:
  cannot create the pointer alignment guard of obj because json_object const is an incomplete type
ov.inst.c:354:60: error: invalid application of ‘sizeof’ to incomplete type ‘json_object’
ov.inst.c:361:45: error: invalid application of ‘sizeof’ to incomplete type ‘json_object’
e-acsl-gcc: fatal error: fail to compile/link instrumented code
```

Replacing `\valid_read(obj)` with `\initialized(obj)` fails the same way.

## Proposed fix

When E-ACSL meets one of these terms, ignore the annotation with a "not yet supported" warning,
which is what it does for every other construct it cannot translate:

1. In typing, reject `sizeof`/`alignof` of an incomplete struct or union. This covers the RTE
   alignment assertion.
2. In `memory_translate.ml`, reject memory predicates whose pointee is incomplete, before any
   `sizeof` is built. This covers `\valid`, `\valid_read`, `\initialized` and their range forms.
   The check cannot sit in typing: translating `\valid` does not consult the typing errors of the
   predicate, so a typing error there makes translation fail with
   `Failure: typing was not performed on construct obj` (tried).

`void` and function types are left out of both checks. `sizeof(void)` is a GNU extension (value 1)
that gcc and clang accept, so `\valid(p)` on a `void *` compiles today, and the patch keeps it that
way.

```diff
--- a/plugins/e-acsl/src/analyses/typing.ml
+++ b/plugins/e-acsl/src/analyses/typing.ml
@@ -16,6 +16,13 @@ open Analyses_datatype
 let dkey = Options.Dkey.typing
 module Error = Error.Make(struct let phase = dkey end)
 
+(* An incomplete struct or union has no size nor alignment: [sizeof] or
+   [alignof] of such a type would not compile. *)
+let is_incomplete_type ty =
+  not (Ast_types.C.is_void ty
+       || Ast_types.C.is_fun ty
+       || Cil.isCompleteType ty)
+
 (* In order to properly handle recursive functions the typing method has to
    store the result of the fixpoint algorithm on intervals before typing
    the inner block of the function. To this end, we stop the recursive
@@ -341,6 +348,8 @@ let rec type_term
        (and of course also covers the missing cases). Also enforce the invariant
        that every subterm is typed, even if it is not an integer. *)
     match t.term_node with
+    | TSizeOf ty | TAlignOf ty when is_incomplete_type ty ->
+      Error.not_yet "sizeof or alignof of an incomplete type"
     | TConst (Boolean _ | Integer _ | LChr _ | LEnum _ | LReal _)
     | TSizeOf _
     | TAlignOf _ ->
--- a/plugins/e-acsl/src/code_generator/memory_translate.ml
+++ b/plugins/e-acsl/src/code_generator/memory_translate.ml
@@ -167,6 +167,14 @@ let gmp_to_sizet ~adata ~loc ?pp kf env size _p =
     env
     size
 
+(* The memory built-ins take the size of the pointed type, which an incomplete
+   struct or union does not have: [sizeof] of it would not compile. *)
+let check_complete_pointee ty =
+  if not (Ast_types.C.is_void ty
+          || Ast_types.C.is_fun ty
+          || Cil.isCompleteType ty)
+  then Error.not_yet "memory predicate on a pointer to an incomplete type"
+
 (* Take a term of the form [ptr + r] where [ptr] is an address and [r] a range
    offset, and return a tuple [(ptr, size, env)] where [ptr] is the address of
    the start of the range, [size] is the size of the range in bytes and [env] is
@@ -186,6 +194,7 @@ let range_to_ptr_and_size ~adata ~loc kf env ptr r p =
     | TPtr ty | TArray (ty, _) -> ty
     | _ -> assert false
   in
+  check_complete_pointee ty;
   let s = Logic_const.term ~loc (TSizeOf ty) Linteger in
   (* ptr *)
   let typ_charptr = Cil_const.charPtrType in
@@ -272,12 +281,13 @@ let range_to_ptr_and_size ~adata ~loc kf env ptr r p =
    [ptr] is an expression representing [t], [sizeof] is the size of the
    expression in bytes. [adata] and [env] as usual. *)
 let term_to_ptr_and_size ~adata ~loc kf env t =
+  let ty = Misc.unghost_type @@ Misc.cty t.term_type in
+  check_complete_pointee (Ast_types.C.direct_pointed ty);
   let (e, adata), env =
     Env.with_params_and_result ~env (fun env ->
         let e, adata, env = Translate_terms.to_exp ~adata kf env t in
         (e, adata), env)
   in
-  let ty = Misc.unghost_type @@ Misc.cty t.term_type in
   let sizeof = Smart_exp.ptr_sizeof ~loc ty in
   let adata =
     Assert.register
```

`term_to_ptr_and_size` now computes `ty` before translating the term. This keeps the check ahead
of any statement the translation would add to `env`.

### Alternatives for the maintainers

- **On the RTE side**: `pointer_alignment` (`rte.ml:463`) and `trivially_aligned` (`rte.ml:425`)
  could skip the assertion when the target type is incomplete, as E-ACSL's own guard does. Eva and
  WP would then not see `alignof` of an incomplete type either. The typing change above is still
  needed for user-written `sizeof`/`alignof`.
- **A weaker check instead of none**: for `\valid(obj)` with an incomplete pointee, E-ACSL could
  check that `obj` points into an allocated block (one byte), rather than dropping the annotation.
  That is a semantic choice, so the patch only drops it.

## Validation of the proposed fix

Built from `ad24dca` with the patch:

| Check | `master` | Patched |
|---|---|---|
| `e-acsl-gcc -F -rte opaque_cast.c`, clang and gcc | compile error (`__alignof__`) | `E-ACSL construct 'sizeof or alignof of an incomplete type' is not yet supported. Ignoring annotation.`; builds; runs, exit 0 |
| `e-acsl-gcc opaque_valid.c` | compile error (`sizeof`) | `E-ACSL construct 'memory predicate on a pointer to an incomplete type' is not yet supported. Ignoring annotation.`; builds; runs, exit 0 |
| `e-acsl-gcc opaque_init.c` (`\initialized(obj)`) | compile error (`sizeof`) | same warning; builds; runs, exit 0 |
| ptests `plugins/e-acsl/tests` (default and `dev` configurations), `plugins/rte/tests` | — | no change |

## Workaround

Make the struct complete in the translation unit given to E-ACSL (include the private header), or
keep `\valid`/`\initialized` and `-rte` alignment assertions off functions that take opaque
handles.
