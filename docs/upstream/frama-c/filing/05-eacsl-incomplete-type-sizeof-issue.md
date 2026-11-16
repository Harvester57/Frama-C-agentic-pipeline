# [E-ACSL] Annotations on pointers to an incomplete (opaque) struct emit `sizeof`/`__alignof__` of the incomplete type: the instrumented code does not compile

<!-- Everything below this line is the issue description. -->

### Summary

When an annotation involves a pointer to an incomplete (opaque) struct type, E-ACSL generates `sizeof` and `__alignof__` of that type, so the instrumented file does not compile with gcc or clang. Opaque handles (`typedef struct ctx ctx;`) are common in C APIs.

### Steps to reproduce the issue

Opaque handles are common in C APIs (`typedef struct json_object json_object;` in a public
header, the struct defined only inside the library).

`ov.c` (user contract):

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

`oc.c` (RTE assertion):

```c
typedef struct json_object json_object;

json_object *from_void(void *p) {
  return (json_object *)p;
}

int main(void) {
  return from_void(0) != 0;
}
```

```sh
e-acsl-gcc -o ov.inst.c -O ov ov.c
e-acsl-gcc -F -rte -o oc.inst.c -O oc oc.c
```

### Expected behaviour

The programs are instrumented and build. An annotation that E-ACSL cannot translate because the
pointed type has no size is ignored with a warning, as for other unsupported constructs.

### Actual behaviour

E-ACSL emits `sizeof(json_object)` / `__alignof__(json_object)` and the compiler rejects it:

```text
[e-acsl] ov.c:3: Warning:
  cannot create the pointer alignment guard of obj because json_object const is an incomplete type
[e-acsl] ov.c:3: Warning:
  cannot create the pointer alignment guard of obj because json_object const is an incomplete type
ov.inst.c:354:60: error: invalid application of ‘sizeof’ to incomplete type ‘json_object’
ov.inst.c:361:45: error: invalid application of ‘sizeof’ to incomplete type ‘json_object’
e-acsl-gcc: fatal error: fail to compile/link instrumented code
```

```text
[e-acsl] oc.c:4: Warning:
  cannot create the pointer alignment guard of p because void is an incomplete type
oc.inst.c:322:56: error: invalid application of ‘__alignof__’ to incomplete type ‘json_object’
oc.inst.c:325:45: error: invalid application of ‘__alignof__’ to incomplete type ‘json_object’
e-acsl-gcc: fatal error: fail to compile/link instrumented code
```

`\initialized(obj)` and `\valid(obj)` fail the same way. clang rejects the code too.

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at 3dff90fc70; also 34.0~beta (Selenium)
- Plug-in used: E-ACSL (`e-acsl-gcc`), RTE
- OS name: Debian GNU/Linux
- OS version: 13 (trixie)

### Additional information (optional)

**Cause.** E-ACSL already knows the case: for its own alignment and pointer guards it checks
`Cil.isCompleteType` and warns instead (`plugins/e-acsl/src/analyses/rte_analysis.ml:515` and
`:566`, the warning above). The other terms have no such check:

- `\valid`, `\valid_read`, `\initialized` build the size of the pointed type in
  `term_to_ptr_and_size` (`plugins/e-acsl/src/code_generator/memory_translate.ml:274-281`,
  `Smart_exp.ptr_sizeof`) and `range_to_ptr_and_size` (`:175-189`, `TSizeOf ty`);
- `\aligned(p, alignof(json_object))`, added by `-rte` (`pointer_alignment`) for the cast, is
  typed and translated as is (`plugins/e-acsl/src/analyses/typing.ml:343-346`).

**Fix.** Ignore these annotations with the usual "not yet supported" warning:

1. in typing, reject `sizeof`/`alignof` of an incomplete struct or union (covers the RTE
   alignment assertion and user-written `sizeof`/`alignof`);
2. in `memory_translate.ml`, reject memory predicates whose pointee is incomplete, before any
   statement is generated (covers `\valid`, `\valid_read`, `\initialized` and their range forms).
   The check cannot sit in typing: translating `\valid` does not consult the typing errors of the
   predicate.

`void` and function types are left out of both checks: `sizeof(void)` is accepted by gcc and clang,
so `\valid` on a `void *` keeps working. With the fix:

```text
[e-acsl] ov.c:3: Warning:
  E-ACSL construct `memory predicate on a pointer to an incomplete type'
  is not yet supported.
  Ignoring annotation.
```

```text
[e-acsl] oc.c:4: Warning:
  E-ACSL construct `sizeof or alignof of an incomplete type'
  is not yet supported.
  Ignoring annotation.
```

(next to the existing "cannot create the pointer alignment guard" warnings), and both programs
build and run (exit 0).

Other options for the maintainers: RTE could skip `pointer_alignment` when the target type is
incomplete, as E-ACSL's own guard does (the typing check would still be needed for user-written
`sizeof`/`alignof`); and for `\valid(obj)` E-ACSL could check that `obj` points into an allocated
block instead of dropping the annotation, which is a semantic choice.

Workaround: make the struct complete in the translation unit given to E-ACSL, or keep `\valid`,
`\initialized` and `-rte` off functions that take opaque handles.

A merge request with a fix follows.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
