# [E-ACSL] Formal parameters are never marked initialized: `\initialized` on a by-value struct field or through `&formal` fails on every call (#177 is back)

<!-- Everything below this line is the issue description. -->

### Summary

E-ACSL registers each formal parameter in its shadow memory but never marks it initialized. So `\initialized` on a field of a struct passed by value, or through `&formal`, fails on every call although the argument is fully initialized. This is closed issue #177 failing again.

### Steps to reproduce the issue

This is the bug of #177 ("Incorrect handling of \initialized when initialized struct is passed to
a function by value"), closed in 2022 as no longer failing. It fails again.

`f.c`, no option needed:

```c
struct S { const void *p; unsigned long len; };

/*@ requires \initialized(&s.len); */
int f_req(struct S s) { return s.len > 3; }

int main(void) {
  struct S full = { 0, 5 }; /* fully initialized */
  return f_req(full) - 1;
}
```

`k.c`, with initialization checks:

```c
int f_scalar(int k) {
  k = 7;
  int *pk = &k;
  return *pk * 2;
}

int main(void) {
  return f_scalar(3) - 14;
}
```

`m.c`, for `main`'s own parameters (`argc` and `argv`), no option needed:

```c
int main(int argc, char **argv) {
  int *p = &argc;
  char ***q = &argv;
  /*@ assert \initialized(p); */
  /*@ assert \initialized(q); */
  return 0;
}
```

```sh
e-acsl-gcc -o f.inst.c -O f f.c && ./f.e-acsl
e-acsl-gcc -F "-rte -rte-initialized @all" -o k.inst.c -O k k.c && ./k.e-acsl
e-acsl-gcc -o m.inst.c -O m m.c && ./m.e-acsl
e-acsl-gcc -m bittree -o mb.inst.c -O mb m.c && ./mb.e-acsl
```

### Expected behaviour

All three programs (including `m.c` under both the default segment model and `-m bittree`) run and
exit 0: the caller (or runtime startup for `main`) initializes every argument, and `k` is even
assigned explicitly before its address is taken.

### Actual behaviour

```text
f.c: In function 'f_req'
f.c:3: Error: Precondition failed:
	The failing predicate is:
	\initialized(&s.len).
	With values at failure point:
	- \initialized(&s.len): 0
```

```text
k.c: In function 'f_scalar'
k.c:4: Error: E-ACSL RTE failed:
	The failing predicate is:
	uninitialized:
		\initialized(pk).
	With values at failure point:
	- uninitialized: \initialized(pk): 0
```

```text
m.c: In function 'main'
m.c:4: Error: Assertion failed:
	The failing predicate is:
	\initialized(p).
	With values at failure point:
	- \initialized(p): 0
```

(all abort, exit status 134; `m.c` fails the same way under both the segment model and `-m bittree`.)
The same happens for any read of a field of a by-value struct parameter when initialization checks
are on (`-e-acsl-rte-initialized`, `-rte -rte-initialized`): every function that reads such a field
aborts on its first call, whatever the caller passed, and nothing after the check is ever reached.
Under a fuzzer, every input that reaches such a function is reported as a crash.

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at `b80fcac74f` (first reproduced on `3dff90fc70`); also 34.0~beta (Selenium)
- Plug-in used: E-ACSL (`e-acsl-gcc`, gcc 14.2.0), RTE
- OS name: Debian GNU/Linux
- OS version: 13 (trixie)

### Additional information (optional)

**Cause.** On function entry, the instrumented function registers each tracked formal with
`__e_acsl_store_block((void *)(& s), 16UL);` but never calls `__e_acsl_full_init((void *)(& s));`,
although the caller has just written the parameter. The call comes from `inject_in_stmt`
(`plugins/e-acsl/src/code_generator/injector.ml:470`), which calls `Memory_observer.store` on the
formals (`plugins/e-acsl/src/code_generator/memory_observer.ml:24`); that emits the store only.

For `main`, `inject_in_stmt` intentionally skips `Memory_observer.store` and delegates tracking of
`argc` and `argv` to `__e_acsl_memory_init(&argc, &argv, ...)` -> `argv_alloca(argc_ref, argv_ref)`
in the runtime observation models. Both `argv_alloca` implementations register `argc_ref` and
`argv_ref` without marking them initialized, even though they immediately initialize `argv[]`,
`*argv`, and `*environ` right below:
- `plugins/e-acsl/share/e-acsl/observation_model/segment_model/e_acsl_segment_observation_model.c`:
  calls `shadow_alloca` for `argc_ref` and `argv_ref` without `initialize_static_region`;
- `plugins/e-acsl/share/e-acsl/observation_model/bittree_model/e_acsl_bittree_observation_model.c`:
  calls `eacsl_store_block` for `argc_ref` and `argv_ref` without `eacsl_initialize`.

The rest of E-ACSL assumes formals are initialized:

- `add_initializer` (`injector.ml:161-168`) emits no `__e_acsl_full_init` for an assignment to a
  whole formal (`may_safely_ignore` is true for `vi.vglob || vi.vformal`), which is why `k = 7;`
  does not help;
- `needs_guard` (`plugins/e-acsl/src/analyses/rte_analysis.ml:493-502`) adds no guard to a read of
  a whole formal, but does for `s.len` and `*pk`, and those checks read shadow memory where the
  formal was never marked initialized.

Globals get the same assumption and are marked: `global_observer.ml:138-140` ("a global is both
allocated and initialized") emits `__e_acsl_store_block` then `__e_acsl_full_init`. That was the
fix of #975 ("Global variables are not marked as initialized"); formals never got the second call.

**Fix.** Where E-ACSL stores the formals, also mark each one initialized, as for globals:
`__e_acsl_store_block((void *)(& s),16UL); __e_acsl_full_init((void *)(& s));`. The
`__gen_e_acsl_<f>` wrapper of a function with a contract gets the same for its own formals. In
addition, mark `argc_ref` and `argv_ref` initialized in `argv_alloca` in both observation models
(`initialize_static_region` in the segment model, `eacsl_initialize` in the bittree model). With
the fix all three programs run and exit 0 (including `m.c` in both segment and bittree models),
#177's kind of program (an `assert \initialized(&s.t)` on a by-value struct) passes, and genuinely
uninitialized data is still reported: an uninitialized local read, and an uninitialized `int`
passed by value (reported at the call site, where the argument is read).

Skipping the guard in `needs_guard` for formals would not be enough: a user annotation
(`requires \initialized(&s.len)` above) and a read through a pointer (`*pk`) consult shadow memory,
so the shadow state itself has to be right.

Cost: a struct passed by value with an uninitialized member is no longer reported when the callee
reads that member. Today that check fails on every call, so it cannot tell the two cases apart. A
more precise variant would copy the argument's initialization state at the call (as temporal
analysis does for its metadata with `__e_acsl_temporal_save_*_parameter` /
`__e_acsl_temporal_pull_parameter`); I have not implemented it.

The fix changes 57 `gen_*.c` oracles of `plugins/e-acsl/tests`: each gets one
`__e_acsl_full_init((void *)(& <formal>));` after a formal's store (210 lines added, none removed).
No existing test checks `\initialized` on a formal, which is why the suite did not catch the
regression.

This issue and the one about `\result` ("false `\initialized(&\result.a)` in postconditions of
functions returning a struct", #2801) are the same family: a variable registered in shadow memory but
never marked initialized. They are independent; the two fixes apply and work together.

A merge request with a fix follows.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
