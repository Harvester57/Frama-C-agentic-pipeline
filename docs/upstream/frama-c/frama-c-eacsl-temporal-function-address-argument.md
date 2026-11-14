# E-ACSL: with `--temporal` and full memory tracking, passing a function's address as an argument aborts the program with `Unreachable`

Draft for the Frama-C tracker (https://git.frama-c.com/pub/frama-c/-/issues). Listed as Issue 15 in
[`./frama-c-e-acsl-issues.md`](./frama-c-e-acsl-issues.md#issue-15-temporal-analysis-aborts-on-a-function-address-argument).

## Summary

With temporal analysis (`e-acsl-gcc --temporal`, i.e. `-e-acsl-temporal-validity`) and full memory
tracking (`-e-acsl-full-mtracking`, `e-acsl-gcc -M`), a callee pulls temporal metadata for every
pointer parameter, including a function-pointer parameter. The call site saves metadata only for the
data-pointer arguments. When the argument is a function's address (`apply(&cb, &v)`), nothing is saved
for it, the runtime finds an unset slot, and the program aborts on a correct call:

```
Unreachable
Aborted (core dumped)
```

Without `-e-acsl-full-mtracking` the callee does not pull the function-pointer parameter and the
program runs. Callback-style APIs are common in C libraries (libmnl's `mnl_attr_parse_nested(nest,
cb, data)` was where we hit it), so temporal analysis cannot be combined with full tracking on them.

## Versions

| | Result |
|---|---|
| `34.0~beta (Selenium)`, opam build, image `framac-analysis:latest` (2026-11-14) | **aborts** |

Debian 13, clang 19.1.7, `-G clang`. Not checked on `master`.

## Reproduction

`fnptr.c`:

```c
static int cb(int x) { return x + 1; }

static int apply(int (*f)(int), int *v) { return f(*v); }

int main(void) {
  int v = 1;
  return apply(&cb, &v) == 2 ? 0 : 1;
}
```

```
$ e-acsl-gcc -c -G clang --temporal -O m fnptr.c && ./m.e-acsl; echo rc=$?
rc=0
$ e-acsl-gcc -c -G clang --temporal -F "-e-acsl-full-mtracking" -O m fnptr.c && ./m.e-acsl; echo rc=$?
Unreachable
Aborted (core dumped)
rc=134
```

The instrumented code (`-n -o im.c`) with full tracking:

```c
static int apply(int (*f)(int ), int *v)
{
  ...
  __e_acsl_temporal_pull_parameter((void *)(& f),0U,8UL);
  __e_acsl_temporal_pull_parameter((void *)(& v),1U,8UL);
  ...
}
...
  __e_acsl_temporal_save_nblock_parameter((void *)(& v),1U);
  tmp = apply(& cb,& v);
```

Parameter 0 is pulled but never saved. `eacsl_temporal_pull_parameter`
(`share/e-acsl/instrumentation_model/e_acsl_temporal.c:66-81`) switches on the slot's
`temporal_flow`; a slot that no `save_*_parameter` call filled hits `private_abort("Unreachable\n")`.

## Expected

Either the callee does not pull temporal metadata for a parameter of function-pointer type (there is
no block to track; this is what happens without full tracking), or the call site saves something
for every pointer argument the callee will pull, for example a "no referent" flow for `&function`.

## Related: callers that are not instrumented

The same abort happens whenever an instrumented function with a pointer parameter is called from
code that is not instrumented, because only an instrumented caller saves the metadata. `main` is
handled. A libFuzzer entry point (`LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)`, called
by libFuzzer's own uninstrumented `main`) is not, so `--temporal` aborts on the first input of any
E-ACSL fuzz target. A wrapper compiled without instrumentation that calls
`__e_acsl_temporal_save_nblock_parameter(data, 0)` before calling the instrumented entry avoids that
part. The E-ACSL manual's temporal section could say that callers must be instrumented.

## Workaround

None that keeps both features. Drop `--temporal`, or drop full tracking (which fuzz targets with no
`main` need, see the E-ACSL manual §3.3.1).

## Tracker

Not filed. No open issue in the 2026-11-09 export
([`./pub-frama-c_work_items_2026-11-09.csv`](./pub-frama-c_work_items_2026-11-09.csv)) mentions
`temporal`.
