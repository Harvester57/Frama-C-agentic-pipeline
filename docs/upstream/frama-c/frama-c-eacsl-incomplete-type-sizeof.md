# E-ACSL: annotations on pointers to incomplete (opaque) struct types produce `sizeof`/`alignof` of the incomplete type, so the instrumented code does not compile

**Filed upstream on 2026-11-15:** issue [#2805](https://git.frama-c.com/pub/frama-c/-/work_items/2805), merge request [!36](https://git.frama-c.com/pub/frama-c/-/merge_requests/36).

Draft bug report for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).

**Filing package:** [issue](./filing/05-eacsl-incomplete-type-sizeof-issue.md), [MR](./filing/05-eacsl-incomplete-type-sizeof-mr.md), [reproducer](./repro/05-eacsl-incomplete-type-sizeof.sh), [patch](./patches/05-eacsl-incomplete-type-sizeof.patch)

## Summary

Opaque handles (`typedef struct json_object json_object;`) and unsized extern arrays
(`extern int a[];`) are common in C APIs. When E-ACSL translates an annotation needing the size
or alignment of an incomplete non-void, non-function type (opaque struct or union, unsized array,
or forward-declared enum), it emits `sizeof(...)` or `__alignof__(...)` into the instrumented
code. Neither compiles, so `e-acsl-gcc` stops with `fail to compile/link instrumented code`.
Four common annotations trigger it:

| Annotation | Where it comes from | Generated C |
|---|---|---|
| `\aligned(p, alignof(json_object))` | RTE `pointer_alignment` on the cast `(json_object *)p` | `__alignof__(json_object)` |
| `\valid_read(obj)` / `\valid(obj)` | user contract on an opaque handle | `sizeof(json_object const)` |
| `\initialized(obj)` | user contract on an opaque handle | `sizeof(json_object const)` |
| `sizeof(g)` / `sizeof(a)` / `alignof(int[])` | user assertion (`TSizeOfE`, `TSizeOf`, `TAlignOf`, `TAlignOfE`) on opaque global or unsized array | `sizeof(struct opaque)`, `sizeof(int [])`, `_Alignof(int [])` |

E-ACSL already knows this case. For its own alignment guards it checks completeness and warns
instead (`rte_analysis.ml:515` and `:566`):

```text
[e-acsl] opaque_valid.c:3: Warning:
  cannot create the pointer alignment guard of obj because json_object const is an incomplete type
```

The terms that come from RTE or from the user (`TSizeOf`, `TAlignOf`, `TSizeOfE`, `TAlignOfE`),
and the memory built-ins (`Smart_exp.ptr_sizeof` in `memory_translate.ml:281`, `TSizeOf ty` in
`range_to_ptr_and_size`), have no such check.

## Versions

- Reproduced on `master` at `b80fcac74f` (2026-11-18, `35.0~~dev (Bromine)`), Debian 13,
  gcc 14.2.0 and clang 19.1.7 (both reject the generated code), with
  [`./repro/05-eacsl-incomplete-type-sizeof.sh`](./repro/05-eacsl-incomplete-type-sizeof.sh).
  Originally reproduced on `3dff90fc70` (2026-11-15) and `ad24dca` (2026-11-02).
- Same output on `34.0~beta (Selenium)` (2026-11-15) for `ov`/`oc`.

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

`opaque_expr.c` (`TSizeOfE` on an opaque struct global and an unsized array):

```c
struct opaque;
extern struct opaque g;
extern int a[];

struct complete {
  int x;
};
struct complete complete_var;

void check_sizeof(void) {
  /*@ assert sizeof(g) > 0; */
  /*@ assert sizeof(a) > 0; */
  /*@ assert sizeof(complete_var) > 0; */
}

int main(void) {
  check_sizeof();
  return 0;
}
```

```text
$ e-acsl-gcc -o oe.inst.c -O oe opaque_expr.c
oe.inst.c:269:43: error: invalid application of ‘sizeof’ to incomplete type ‘struct opaque’
oe.inst.c:276:28: error: invalid application of ‘sizeof’ to incomplete type ‘struct opaque’
oe.inst.c:284:45: error: invalid application of ‘sizeof’ to incomplete type ‘int[]’
oe.inst.c:291:28: error: invalid application of ‘sizeof’ to incomplete type ‘int[]’
e-acsl-gcc: fatal error: fail to compile/link instrumented code
```

## Fix

Patch: [`./patches/05-eacsl-incomplete-type-sizeof.patch`](./patches/05-eacsl-incomplete-type-sizeof.patch),
one commit on `fix/e-acsl-incomplete-type-sizeof` from `b80fcac74f`, "[e-acsl] ignore annotations
needing the size of an incomplete type". It adds the regression test
`plugins/e-acsl/tests/constructs/incomplete_type.c` (an opaque `typedef struct opaque opaque;`
with `extern opaque g;`, an unsized `extern int a[];`, a complete `struct complete complete_var;`
control, `requires \valid_read(obj)` and `requires \initialized(obj)` on a pointer to `opaque`,
a cast from `void *` that gets an RTE alignment assertion with `-rte`, `assert sizeof(g) > 0;`,
`assert sizeof(a) > 0;`, `assert alignof(int[]) > 0;`, and positive control
`assert sizeof(complete_var) > 0;`), with its default-configuration oracles.

When E-ACSL meets one of these terms, ignore the annotation with a "not yet supported" warning,
which is what it does for every other construct it cannot translate:

1. In typing, reject `TSizeOf`, `TAlignOf`, `TSizeOfE`, and `TAlignOfE` of an incomplete
   non-void, non-function type (opaque struct or union, unsized array, or forward-declared enum).
   For `TSizeOfE` and `TAlignOfE`, inspect `Ast_types.Acsl.unroll t'.term_type` before typing `t'`.
   This covers the RTE alignment assertion, user-written `sizeof(T)`/`alignof(T)`, and expression
   forms such as `sizeof(g)` and `sizeof(a)`.
2. In `memory_translate.ml`, reject memory predicates whose pointee is an incomplete non-void,
   non-function type, before any `sizeof` is built. This covers `\valid`, `\valid_read`,
   `\initialized` and their range forms. The check cannot sit in typing: translating `\valid`
   does not consult the typing errors of the predicate, so a typing error there makes translation
   fail with `Failure: typing was not performed on construct obj` (tried).

`void` and function types are left out of both checks. `sizeof(void)` is a GNU extension (value 1)
that gcc and clang accept, so `\valid(p)` on a `void *` compiles today, and the patch keeps it that
way.

```diff
--- a/plugins/e-acsl/src/analyses/typing.ml
+++ b/plugins/e-acsl/src/analyses/typing.ml
@@ -16,6 +16,13 @@ open Analyses_datatype
 let dkey = Options.Dkey.typing
 module Error = Error.Make(struct let phase = dkey end)
 
+(* An incomplete non-void, non-function type has no size nor alignment:
+   [sizeof] or [alignof] of such a type would not compile. *)
+let is_incomplete_type ty =
+  not (Ast_types.C.is_void ty
+       || Ast_types.C.is_fun ty
+       || Cil.isCompleteType ty)
+
 (* In order to properly handle recursive functions the typing method has to
    store the result of the fixpoint algorithm on intervals before typing
    the inner block of the function. To this end, we stop the recursive
@@ -343,6 +350,8 @@ let rec type_term
        (and of course also covers the missing cases). Also enforce the invariant
        that every subterm is typed, even if it is not an integer. *)
     match t.term_node with
+    | TSizeOf ty | TAlignOf ty when is_incomplete_type ty ->
+      Error.not_yet "sizeof or alignof of an incomplete type"
     | TConst (Boolean _ | Integer _ | LChr _ | LEnum _ | LReal _)
     | TSizeOf _
     | TAlignOf _ ->
@@ -361,14 +370,23 @@ let rec type_term
       ty_of_interv ?ctx ~use_gmp_opt:under_lambda i
 
     | Toffset(_, t')
-    | Tblock_length(_, t')
-    | TSizeOfE t'
-    | TAlignOfE t' ->
+    | Tblock_length(_, t') ->
       let i = Interval.get_from_profile ~profile t in
       (* [t'] must be typed, but it is a pointer *)
       ignore (type_term ~use_gmp_opt:true ~ctx:Nan ~profile t');
       ty_of_interv ?ctx i
 
+    | TSizeOfE t'
+    | TAlignOfE t' ->
+      begin match Ast_types.Acsl.unroll t'.term_type with
+        | Ctype ty when is_incomplete_type ty ->
+          Error.not_yet "sizeof or alignof of an incomplete type"
+        | _ ->
+          let i = Interval.get_from_profile ~profile t in
+          ignore (type_term ~use_gmp_opt:true ~ctx:Nan ~profile t');
+          ty_of_interv ?ctx i
+      end
+
     | TBinOp (MinusPP, t1, t2) ->
       let i = Interval.get_from_profile ~profile t in
       (* [t1] and [t2] must be typed, but they are pointers *)
--- a/plugins/e-acsl/src/code_generator/memory_translate.ml
+++ b/plugins/e-acsl/src/code_generator/memory_translate.ml
@@ -167,6 +167,15 @@ let gmp_to_sizet ~adata ~loc ?pp kf env size _p =
     env
     size
 
+(* The memory built-ins take the size of the pointed type, which an incomplete
+   non-void, non-function type does not have: [sizeof] of it would not
+   compile. *)
+let check_complete_pointee ty =
+  if not (Ast_types.C.is_void ty
+          || Ast_types.C.is_fun ty
+          || Cil.isCompleteType ty)
+  then Error.not_yet "memory predicate on a pointer to an incomplete type"
+
 (* Take a term of the form [ptr + r] where [ptr] is an address and [r] a range
    offset, and return a tuple [(ptr, size, env)] where [ptr] is the address of
    the start of the range, [size] is the size of the range in bytes and [env] is
@@ -186,6 +195,7 @@ let range_to_ptr_and_size ~adata ~loc kf env ptr r p =
     | TPtr ty | TArray (ty, _) -> ty
     | _ -> assert false
   in
+  check_complete_pointee ty;
   let s = Logic_const.term ~loc (TSizeOf ty) Linteger in
   (* ptr *)
   let typ_charptr = Cil_const.charPtrType in
@@ -272,12 +282,13 @@ let range_to_ptr_and_size ~adata ~loc kf env ptr r p =
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
  needed for user-written `sizeof`/`alignof` and `TSizeOfE`/`TAlignOfE`.
- **A weaker check instead of none**: for `\valid(obj)` with an incomplete pointee, E-ACSL could
  check that `obj` points into an allocated block (one byte), rather than dropping the annotation.
  That is a semantic choice, so the patch only drops it.

## Validation of the fix

Validated end-to-end on `b80fcac74f` in a fresh `framac-master-audit:b80fcac` container via
`JOBS=4 /w/revalidate.sh before 05` and `JOBS=4 /w/revalidate.sh package 05` (Debian 13, OCaml 5.5
switch, gcc 14.2.0, clang 19.1.7), 2026-11-18:

| Check | `master` `b80fcac74f` | Patched |
|---|---|---|
| `e-acsl-gcc -F -rte 05-eacsl-incomplete-type-sizeof-cast.c` | compile error (`__alignof__`) | `E-ACSL construct 'sizeof or alignof of an incomplete type' is not yet supported. Ignoring annotation.`; builds; runs, exit 0 |
| `e-acsl-gcc 05-eacsl-incomplete-type-sizeof.c` | compile error (`sizeof`) | `E-ACSL construct 'memory predicate on a pointer to an incomplete type' is not yet supported. Ignoring annotation.`; builds; runs, exit 0 |
| `e-acsl-gcc 05-eacsl-incomplete-type-sizeof-expr.c` (`sizeof(g)`, `sizeof(a)`, `sizeof(complete_var)`) | compile error (`sizeof` on `struct opaque` and `int[]`) | warnings on `g`/`a`, complete control checked; builds; runs, exit 0 |
| the three programs above with `-G clang` (clang 19.1.7) | compile error (`sizeof`/`alignof`) | builds; runs, exit 0 |
| `./dev/test.sh -p plugins/e-acsl/tests/constructs/incomplete_type.c` (default and `-c dev`) | fails (exit 1) in both default and `dev` | passes (exit 0) in both default and `dev` |
| `./dev/test.sh -p plugins/e-acsl` (default configuration, full E-ACSL suite) | — | passes (exit 0) |
| `./dev/check-files.sh -p HEAD~1` (5 changed files, `ocp-indent` 1.10.0, `clang-format` 19.1.7) | — | passes (exit 0) |

Earlier validation on `3dff90fc70` (2026-11-15) also checked `\valid(obj)` and `\initialized(obj)`
individually, and on `ad24dca` (2026-11-02) also ran `plugins/rte/tests` with no change.

## Workaround

Make the struct complete in the translation unit given to E-ACSL (include the private header), or
keep `\valid`/`\initialized` and `-rte` alignment assertions off functions that take opaque
handles.
