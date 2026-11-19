# [E-ACSL] Annotations on pointers to an incomplete (opaque) struct emit `sizeof`/`__alignof__` of the incomplete type: the instrumented code does not compile

<!-- Everything below this line is the issue description. -->

### Summary

When an annotation involves an incomplete non-void, non-function type (an opaque struct or union, an unsized array such as `extern int a[]`, or a forward-declared enum), E-ACSL generates `sizeof` or `__alignof__` of that type, so the instrumented file does not compile with gcc or clang. Opaque handles (`typedef struct ctx ctx;`) and extern unsized arrays are common in C APIs.

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

`oe.c` (`TSizeOfE` on an opaque struct global and an unsized array):

```c
struct opaque;
extern struct opaque g;
extern int a[];

void check_sizeof(void) {
  /*@ assert sizeof(g) > 0; */
  /*@ assert sizeof(a) > 0; */
}

int main(void) {
  check_sizeof();
  return 0;
}
```

```sh
e-acsl-gcc -o oe.inst.c -O oe oe.c
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

`\initialized(obj)` and `\valid(obj)` fail the same way, and `oe.c` fails with:

```text
oe.inst.c:269:43: error: invalid application of ‘sizeof’ to incomplete type ‘struct opaque’
oe.inst.c:276:28: error: invalid application of ‘sizeof’ to incomplete type ‘struct opaque’
oe.inst.c:284:45: error: invalid application of ‘sizeof’ to incomplete type ‘int[]’
oe.inst.c:291:28: error: invalid application of ‘sizeof’ to incomplete type ‘int[]’
e-acsl-gcc: fatal error: fail to compile/link instrumented code
```

clang rejects the code too.

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at `b80fcac74f` (originally reported on `3dff90fc70`); also 34.0~beta (Selenium)
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
- `\aligned(p, alignof(json_object))`, added by `-rte` (`pointer_alignment`) for the cast, and
  user-written `sizeof(T)`/`alignof(T)` (`TSizeOf`/`TAlignOf`) as well as expression forms
  `sizeof(e)` (`TSizeOfE`) and `TAlignOfE` are typed and translated as is
  (`plugins/e-acsl/src/analyses/typing.ml:346-370`).

**Fix.** Ignore these annotations with the usual "not yet supported" warning:

1. in typing, reject `TSizeOf`, `TAlignOf`, `TSizeOfE` and `TAlignOfE` of an incomplete
   non-void, non-function type (covers the RTE alignment assertion, user-written
   `sizeof(T)`/`alignof(T)`, and `sizeof(e)`/`TAlignOfE` on expressions of incomplete struct,
   union, array, or enum type);
2. in `memory_translate.ml`, reject memory predicates whose pointee is an incomplete non-void,
   non-function type, before any statement is generated (covers `\valid`, `\valid_read`,
   `\initialized` and their range forms). The check cannot sit in typing: translating `\valid`
   does not consult the typing errors of the predicate.

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
