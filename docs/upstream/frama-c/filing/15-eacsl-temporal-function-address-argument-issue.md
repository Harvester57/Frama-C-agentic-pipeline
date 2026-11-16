# [E-ACSL] `--temporal`: a callee pulls parameter metadata that its caller never saved, and the program aborts with "Unreachable"

<!-- Everything below this line is the issue description. -->

### Summary

With `--temporal`, a callee reads the temporal metadata of a parameter that its caller never saved, and the program aborts with "Unreachable". This happens when the argument is a function's address, or a constant passed to an annotated formal, which blocks temporal analysis of callback APIs. Three possible fixes are listed below.

### Steps to reproduce the issue

`fnptr.c`, a function's address passed as an argument:

```c
static int cb(int x) { return x + 1; }

static int apply(int (*f)(int), int *v) { return f(*v); }

int main(void) {
  int v = 1;
  return apply(&cb, &v) == 2 ? 0 : 1;
}
```

```
$ e-acsl-gcc -c --temporal -O prog fnptr.c && ./prog.e-acsl; echo $?
$ e-acsl-gcc -c --temporal -M -O prog fnptr.c && ./prog.e-acsl; echo $?
```

`null.c`, a constant passed to a formal that an annotation makes E-ACSL track (no `-M` needed):

```c
static int get(int *p) {
  /*@ assert \valid_read(&p); */
  return p ? *p : 0;
}

int main(void) { return get((int *)0); }
```

```
$ e-acsl-gcc -c --temporal -O prog null.c && ./prog.e-acsl; echo $?
```

### Expected behaviour

The programs are correct and exit with 0 when instrumented, as they do without `--temporal`.

### Actual behaviour

`fnptr.c` runs without `-M` (exit code 0) but aborts with full memory tracking:

```
Unreachable
Aborted (core dumped)
134
```

`null.c` aborts the same way with the default options. The instrumented `fnptr.c` (`-M`) shows the
mismatch:

```c
static int apply(int (*f)(int ), int *v)
  ...
  __e_acsl_temporal_pull_parameter((void *)(& f),0U,8UL);
  __e_acsl_temporal_pull_parameter((void *)(& v),1U,8UL);
...
  __e_acsl_temporal_save_nblock_parameter((void *)(& v),1U);
  tmp = apply(& cb,& v);
```

Parameter 0 is pulled but never saved. Passing a function pointer variable (`int (*g)(int) = &cb;
apply(g, &v);`) works, and so does `(void *)&cb` passed to a `void *` formal without `-M` (it
aborts with `-M`).

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at 3dff90fc70; also 34.0~beta (Selenium)
- Plug-in used: E-ACSL (`e-acsl-gcc --temporal`, i.e. `-e-acsl-temporal-validity`; with and without `-M`)
- OS name: Debian GNU/Linux
- OS version: 13 (trixie)

### Additional information (optional)

The caller and the callee decide independently whether a parameter's temporal metadata is passed,
and with different rules:

- The callee pulls one parameter for each formal that the memory-tracking analysis monitors
  (`Temporal.handle_function_parameters`, `plugins/e-acsl/src/code_generator/temporal.ml:469-481`,
  `track_argument` at line 387).
- The caller saves an argument only when the argument's base variable is monitored
  (`save_params`, `temporal.ml:231-252`; the test is `Memory_tracking.must_monitor_exp ~kf param` at
  line 240).

The memory-tracking analysis propagates the monitoring of a formal to the base variable of the
argument, so the two rules agree when that base exists and can be monitored. They disagree when it
does not:

- a function's address: `must_never_monitor` (`plugins/e-acsl/src/analyses/memory_tracking.ml:59-79`)
  excludes variables of function type ("function pointers are not yet supported"), while the
  callee's formal of type pointer-to-function is monitored under `-M` like any other;
- a constant (`NULL`, an integer cast to a pointer): `apply_on_vi_base_from_exp` returns false for
  `Const`, so without `-M` nothing is saved, while an annotation can make the callee monitor its
  formal.

`eacsl_temporal_pull_parameter`
(`plugins/e-acsl/share/e-acsl/instrumentation_model/e_acsl_temporal.c:66-81`) then finds the slot
that `eacsl_temporal_reset_parameters` cleared before the call and reaches
`private_abort("Unreachable\n")`.

I did not write a patch because the fix is a choice between rules that I would rather leave to the
maintainers:

1. **Save at the call site whatever the callee may pull.** For a direct call to a defined function,
   save argument `i` if and only if the callee's formal `i` is monitored, which is exactly the
   callee's rule. For a call through a pointer, the callee is unknown: save every argument of
   pointer or struct type. For a function's address or a constant, an `nblock` save makes the pull
   store `origin_timestamp` of that address, which is the invalid timestamp for an address outside
   the tracked segments. This keeps the abort as a consistency check, but adds saves (and changes
   the oracles of the temporal tests).
2. **Do not pull a formal of pointer-to-function type** in the callee, consistent with
   `must_never_monitor`. Small, but it covers only `fnptr.c`: `null.c` and `(void *)&cb` passed to a
   `void *` formal still abort.
3. **Make the pull tolerate an unset slot**: store the invalid timestamp instead of aborting. This
   covers every case above, and would also cover callers that are not instrumented at all (for
   example a libFuzzer entry point `LLVMFuzzerTestOneInput`, called by libFuzzer's own `main`,
   which never saves its arguments), but it removes the check that caught this inconsistency.

Workaround: none that keeps temporal analysis and full memory tracking on such code.

The analysis was prepared with LLM assistance (Claude Code); I reviewed it and ran the reproducers
described above.
