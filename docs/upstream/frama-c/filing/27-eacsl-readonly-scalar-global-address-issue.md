# [E-ACSL] __e_acsl_mark_readonly gets the value of a const global instead of its address: "Use of invalid address" at start-up for a scalar

<!-- Everything below this line is the issue description. -->

### Summary

For a `const` global that is neither an array nor a struct, E-ACSL passes the global's value instead of its address to `__e_acsl_mark_readonly`. For a scalar such as `const uint64_t k = 23;`, every instrumented program aborts at start-up with "Use of invalid address 0x17". A `const` union does not compile, and for a pointer its target is marked instead of the pointer. For a `const` struct, E-ACSL emits one call per field address, which aborts Frama-C on a bitfield member, emits no call for an empty struct, and writes read-only shadow bits past the end of the struct on any non-first field (aborting under `--rt-debug` with "Attempt to mark read-only ... bytes past block boundaries", and corrupting adjacent global shadow memory without `--rt-debug`).

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

`s.c`, a multi-field const struct:

```c
struct pair {
  int a;
  int b;
};

static const struct pair cp = { 1, 2 };

int main(void)
{
  return cp.a + cp.b != 3;
}
```

```sh
e-acsl-gcc -q -X -M -o k.inst.c -O k k.c && ./k.e-acsl
e-acsl-gcc -q -X -M -o b.inst.c -O b b.c
e-acsl-gcc -q -X -M --rt-debug -o s.inst.c -O s s.c && ./s.e-acsl
```

(`-M` is `-e-acsl-full-mtracking`. Without it, these globals are not monitored and the programs run.)

### Expected behaviour

All three programs are instrumented, compile and exit 0, with the const globals marked read-only once from their base address.

### Actual behaviour

`k.c` instruments, but the generated globals initializer passes the value of the global:

```c
    __e_acsl_mark_readonly((void *)kMaxEmbeddedInt);
```

and the program aborts before `main` does anything:

```text
/home/opam/.opam/5.5/bin/../share/frama-c/share/e-acsl/observation_model/segment_model/e_acsl_segment_tracking.c:226: Use of invalid address 0x17 in predicate
Aborted
```

`b.c` does not instrument:

```text
[kernel] Failure: Taking the address of a bitfield with &[ cb.a ]
[kernel] Frama-C aborted: internal error (Taking the address of a bitfield with &[ cb.a ]).
  Please report as 'crash' at https://git.frama-c.com/pub/frama-c/issues
e-acsl-gcc: fatal error: aborted by Frama-C
```

`s.c` instruments with one call per field:

```c
    __e_acsl_mark_readonly((void *)(& cp.a));
    __e_acsl_mark_readonly((void *)(& cp.b));
```

and under `--rt-debug` aborts before `main` runs:

```text
share/e-acsl/observation_model/segment_model/e_acsl_segment_tracking.c:497: Attempt to mark read-only 8 bytes past block boundaries
starting at 0x41-500c with block length 8 at base address 0x41-5008
Aborted
```

A const union global fails too, with `User Error: implicit cast: cast from union u to void *`: see
#2795. A const pointer global `int *const p = &x;` gets `__e_acsl_mark_readonly((void *)p)`, which
marks the block `p` points to rather than `p`.

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at b80fcac74f (also reproduced on 3dff90fc70 and 34.0~beta (Selenium))
- Plug-in used: E-ACSL (`e-acsl-gcc`)
- OS name: Debian GNU/Linux
- OS version: 13 (trixie)

### Additional information (optional)

**Cause.** `Global_observer.mk_init_function` (`plugins/e-acsl/src/code_generator/global_observer.ml:121-136`)
builds the `__e_acsl_mark_readonly` calls for const globals. The runtime's
`eacsl_mark_readonly(void *ptr)` (`e_acsl_segment_observation_model.c:118-122`) calls
`mark_readonly_region((uintptr_t)ptr, _block_length(ptr))`, where `_block_length(ptr)` is the size of
the whole enclosing block, so it expects the base address of the block.
Structs instead get one call per field with `Cil.mkAddrOf`, which:
- passes a non-zero offset for every field after the first, writing `_block_length(ptr)` read-only
  shadow bits past the end of the struct (aborting `DVASSERT` at `e_acsl_segment_tracking.c:497` under
  `--rt-debug`, and corrupting adjacent global shadow memory without `--rt-debug`);
- aborts Frama-C on a bitfield member (`src/kernel/services/ast_queries/cil.ml:4874`);
- emits zero calls for an empty struct.
Every other type gets `Cil.evar ~loc vi` (line 130), the value of the global: right for an array, which
decays to its address, wrong for a scalar or a pointer, and not a valid cast for a union. The struct
branch came with e-acsl#223 (`dc9cf84924`), which fixed the same typing error for structs; the
`Cil.evar` call dates from `15b2c6f412` ("mark const globals as readonly").

**Fix.** Remove the per-field struct branch and pass `Cil.mkAddrOfVi vi` for every type but arrays
(keeping `Cil.evar` for arrays, which decay to their base address, so the generated code for string
literals does not change). A merge request with a fix follows; it also fixes #2795.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
