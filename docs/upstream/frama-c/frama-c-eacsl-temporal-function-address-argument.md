# E-ACSL: with `--temporal`, a callee pulls parameter metadata that its caller never saved (a function's address under full tracking, a constant to a tracked formal), and the program aborts with `Unreachable`

**Filed upstream on 2026-11-15:** issue [#2815](https://git.frama-c.com/pub/frama-c/-/work_items/2815), no merge request (the fix is the maintainers' choice).

Draft for the Frama-C tracker (https://git.frama-c.com/pub/frama-c/-/issues). Listed as Issue 15 in
[`./frama-c-e-acsl-issues.md`](./frama-c-e-acsl-issues.md#issue-15-temporal-analysis-aborts-on-a-function-address-argument).

**Filing package:** [issue](./filing/15-eacsl-temporal-function-address-argument-issue.md), [reproducer](./repro/15-eacsl-temporal-function-address-argument.sh). No patch and no MR: the fix is a design choice for the maintainers (see [Options](#options-no-patch)).

## Summary

With temporal analysis (`e-acsl-gcc --temporal`, i.e. `-e-acsl-temporal-validity`), an instrumented
callee pulls temporal metadata for each formal that the memory-tracking analysis monitors, while the
caller saves metadata only for the arguments whose base variable is monitored. When the two rules
disagree, the callee pulls an empty slot and the runtime aborts on a correct program:

```
Unreachable
Aborted (core dumped)
```

Two ways to get there, both checked on `master`:

- a function's address passed as an argument with full memory tracking (`-e-acsl-full-mtracking`,
  `e-acsl-gcc -M`): `apply(&cb, &v)`. Under `-M` the callee monitors its pointer-to-function formal,
  but the caller never saves `&cb`, since a variable of function type is never monitored;
- a constant (`NULL`) passed to a formal that an annotation makes E-ACSL track, with the default
  options: the analysis has no base variable to monitor for a constant, so nothing is saved.

Callback-style APIs are common in C libraries (libmnl's `mnl_attr_parse_nested(nest, cb, data)`
was where we hit it), so temporal analysis cannot be combined with full tracking on them.

## Versions

| | Result |
|---|---|
| `35.0~~dev (Bromine)`, `master` at `3dff90fc70`, image `framac-master-audit:3dff90f` | **aborts** (both reproducers) |
| `34.0~beta (Selenium)`, image `framac-analysis:fc34` | **aborts** (both reproducers) |

Debian 13, gcc 14 (default) and clang 19.

## Reproduction

[`./repro/15-eacsl-temporal-function-address-argument.sh`](./repro/15-eacsl-temporal-function-address-argument.sh)
builds [`./repro/15-eacsl-temporal-function-address-argument.c`](./repro/15-eacsl-temporal-function-address-argument.c)
without and with `-M`, and
[`./repro/15-eacsl-temporal-function-address-argument-null.c`](./repro/15-eacsl-temporal-function-address-argument-null.c)
with the default options:

```c
static int cb(int x) { return x + 1; }

static int apply(int (*f)(int), int *v) { return f(*v); }

int main(void) {
  int v = 1;
  return apply(&cb, &v) == 2 ? 0 : 1;
}
```

```c
static int get(int *p) {
  /*@ assert \valid_read(&p); */
  return p ? *p : 0;
}

int main(void) { return get((int *)0); }
```

On `master`:

```
== e-acsl-gcc --temporal 15-eacsl-temporal-function-address-argument.c
e-acsl-gcc exit code: 0
prog.e-acsl exit code: 0
== e-acsl-gcc --temporal -M 15-eacsl-temporal-function-address-argument.c
e-acsl-gcc exit code: 0
Unreachable
prog.e-acsl exit code: 134
== e-acsl-gcc --temporal 15-eacsl-temporal-function-address-argument-null.c
e-acsl-gcc exit code: 0
Unreachable
prog.e-acsl exit code: 134
== temporal calls in the instrumented code (-M):
__e_acsl_temporal_pull_parameter((void *)(& f),0U,8UL);
__e_acsl_temporal_pull_parameter((void *)(& v),1U,8UL);
__e_acsl_temporal_save_nblock_parameter((void *)(& v),1U);
tmp = apply(& cb,& v);
```

Other variants (`master`, `--temporal`):

| Variant | default | `-M` |
|---|---|---|
| `apply(&cb, &v)` | exit 0 | **Unreachable** |
| `apply(cb, &v)` (no `&`) | exit 0 | **Unreachable** |
| `int (*g)(int) = &cb; apply(g, &v)` (function pointer variable) | exit 0 | exit 0 |
| `call((void *)&cb, &v)` with a `void *` formal | exit 0 | **Unreachable** |
| `apply(&cb, &v)` with `/*@ assert \valid_read(&f); */` in `apply` | **Unreachable** | **Unreachable** |
| `get(&x)` (local or global `x`, string literal) with `\valid_read(&p)` in `get` | exit 0 | exit 0 |
| `get((int *)0)` with `\valid_read(&p)` in `get` | **Unreachable** | exit 0 |

## Analysis

On `master` `3dff90fc70`:

- Callee: `Temporal.handle_function_parameters`
  (`plugins/e-acsl/src/code_generator/temporal.ml:469-481`) calls `track_argument` (line 387),
  which emits `__e_acsl_temporal_pull_parameter`, for each formal with
  `Memory_tracking.must_monitor_vi ~kf param`.
- Caller: `Function_call.save_params` (`temporal.ml:231-252`) emits `save_*_parameter` for an
  argument only if `Memory_tracking.must_monitor_exp ~kf param` (line 240), which looks at the base
  variable of the argument.
- `Memory_tracking.must_never_monitor` (`plugins/e-acsl/src/analyses/memory_tracking.ml:59-79`)
  excludes variables of function type ("function pointers are not yet supported"), so
  `must_monitor_exp` is false for `&cb`, even under `-M`. The formal `f`, of pointer type, is not
  excluded.
- `apply_on_vi_base_from_exp` returns false for `Const`, so without `-M` a constant argument is not
  saved. Under `-M`, `must_monitor_exp` is true unless the base must never be monitored, so `NULL`
  is saved.
- Runtime: `eacsl_temporal_reset_parameters` clears the slots before each call;
  `eacsl_temporal_pull_parameter`
  (`plugins/e-acsl/share/e-acsl/instrumentation_model/e_acsl_temporal.c:66-81`) aborts with
  `private_abort("Unreachable\n")` on a slot that no `save_*_parameter` filled.

The memory-tracking analysis propagates the monitoring of a formal to the base variable of the
actual argument, so the two rules agree when that base exists and may be monitored; they disagree
when it does not (function, constant).

## Options (no patch)

1. **Save at the call site whatever the callee may pull.** For a direct call to a defined function,
   save argument `i` if and only if the callee's formal `i` is monitored (the callee's own rule).
   For a call through a pointer, the callee is unknown: save every argument of pointer or struct
   type. An `nblock` save of a function's address or a constant makes the pull store
   `origin_timestamp` of that address, which is the invalid timestamp outside the tracked segments
   (`TRY_SEGMENT_WEAK`). Keeps the abort as a consistency check; adds saves and changes the oracles
   of the `temporal` tests.
2. **Do not pull formals of pointer-to-function type** in the callee, consistent with
   `must_never_monitor`. Small, but covers only the `&cb`/`cb` rows above: `NULL`, `(void *)&cb` to
   a `void *` formal, and the annotated `apply` still abort.
3. **Make the pull tolerate an unset slot** (store the invalid timestamp). Covers every row, and
   would also cover callers that are not instrumented (a libFuzzer entry point called by
   libFuzzer's own `main`, see below), but removes the check that caught the inconsistency.

A narrow call-site fix ("also save when the base is a function") was considered and rejected: it
does not cover the `NULL` row, which needs no `-M`. None of the options was built.

## Related: callers that are not instrumented

The same abort happens whenever an instrumented function with a tracked pointer parameter is called
from code that is not instrumented, because only an instrumented caller saves the metadata. `main`
is handled. A libFuzzer entry point (`LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)`,
called by libFuzzer's own uninstrumented `main`) is not, so `--temporal` aborts on the first input
of any E-ACSL fuzz target (observed on 34.0~beta in an earlier pipeline run; not re-checked on
`master`). A wrapper compiled without instrumentation that calls
`__e_acsl_temporal_save_nblock_parameter(data, 0)` before calling the instrumented entry avoids that
part. The E-ACSL manual's temporal section could say that callers must be instrumented.

## Side observation

`eacsl_temporal_save_return` in the same file reads
`return_referent = (ptr, sizeof(void *)) ? referent_timestamp(ptr) : 0;`. The condition is a comma
expression whose value is `sizeof(void *)`, always true, so the `0` branch is dead. It looks like a
call (an allocation or validity test on `ptr`) lost its name. Not investigated further and not
part of this issue.

## Workaround

None that keeps both features. Drop `--temporal`, or drop full tracking (which fuzz targets with no
`main` need, see the E-ACSL manual §3.3.1), and avoid annotations that force a pointer formal to be
tracked when a caller passes a constant.

## Tracker

Not filed at the time of writing (see the filing note at the top). No open issue in the 2026-11-09 export
([`./pub-frama-c_work_items_2026-11-09.csv`](./pub-frama-c_work_items_2026-11-09.csv)) mentions
`temporal`, `pull_parameter` or `Unreachable` with E-ACSL. #182 ("missing E-ACSL code, control flow
graph, function pointer") is about calls through function pointers, not about temporal metadata.
