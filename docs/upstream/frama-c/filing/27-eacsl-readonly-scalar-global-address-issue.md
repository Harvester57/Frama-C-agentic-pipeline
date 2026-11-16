# [E-ACSL] __e_acsl_mark_readonly gets the value of a const global instead of its address: "Use of invalid address" at start-up for a scalar

<!-- Everything below this line is the issue description. -->

### Summary

For a `const` global that is neither an array nor a struct, E-ACSL passes the global's value instead of its address to `__e_acsl_mark_readonly`. For a scalar such as `const uint64_t k = 23;`, every instrumented program aborts at start-up with "Use of invalid address 0x17". A `const` union does not compile, and for a pointer its target is marked instead of the pointer.

### Steps to reproduce the issue

`k.c`:

```c
#include <stdint.h>

const uint64_t kMaxEmbeddedInt = 23;

int main(void)
{
  return kMaxEmbeddedInt != 23;
}
```

`b.c`, a const struct with a bitfield member:

```c
struct B { unsigned a : 3; unsigned b : 5; };
const struct B cb = { 1, 2 };

int main(void)
{
  return cb.a != 1;
}
```

```sh
e-acsl-gcc -q -X -M -o k.inst.c -O k k.c && ./k.e-acsl
e-acsl-gcc -q -X -M -o b.inst.c -O b b.c
```

(`-M` is `-e-acsl-full-mtracking`. Without it, these globals are not monitored and both programs run.)

### Expected behaviour

Both programs are instrumented, compile and exit 0, with the const globals marked read-only.

### Actual behaviour

`k.c` instruments, but the generated globals initializer passes the value of the global:

```c
    __e_acsl_mark_readonly((void *)kMaxEmbeddedInt);
```

and the program aborts before `main` does anything:

```text
/home/opam/.opam/5.5/bin/../share/frama-c/share/e-acsl/observation_model/segment_model/e_acsl_segment_tracking.c:226: Use of invalid address 0x17 in predicate
Aborted (core dumped)
```

`b.c` does not instrument:

```text
[kernel] Failure: Taking the address of a bitfield with &[ cb.a ]
[kernel] Frama-C aborted: internal error (Taking the address of a bitfield with &[ cb.a ]).
  Please report as 'crash' at https://git.frama-c.com/pub/frama-c/issues
e-acsl-gcc: fatal error: aborted by Frama-C
```

A const union global fails too, with `User Error: implicit cast: cast from union u to void *`: see
#2795. A const pointer global `int *const p = &x;` gets `__e_acsl_mark_readonly((void *)p)`, which
marks the block `p` points to rather than `p`. I saw no failure from that one in a small program.

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at 3dff90fc70; also 34.0~beta (Selenium)
- Plug-in used: E-ACSL (`e-acsl-gcc`)
- OS name: Debian GNU/Linux
- OS version: 13 (trixie)

### Additional information (optional)

**Cause.** `Global_observer.mk_init_function` (`plugins/e-acsl/src/code_generator/global_observer.ml:121-136`)
builds the `__e_acsl_mark_readonly` calls for const globals. Structs get one call per field, with
`Cil.mkAddrOf` on the field, which aborts on a bitfield (`src/kernel/services/ast_queries/cil.ml:4874`).
Every other type gets `Cil.evar ~loc vi` (line 130), the value of the global: right for an array, which
decays to its address, wrong for a scalar or a pointer, and not a valid cast for a union. The runtime's
`eacsl_mark_readonly(void *ptr)` expects the address of the block. The struct branch came with
e-acsl#223 (`dc9cf84924`), which fixed the same typing error for structs; the `Cil.evar` call dates from
`15b2c6f412` ("mark const globals as readonly").

**Fix.** Pass `Cil.mkAddrOfVi vi` for every type but arrays (and keep `Cil.evar` for arrays, so the
generated code for string literals does not change), and mark a struct with a bitfield member through its
own address. A merge request with a fix follows; it also fixes #2795.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
