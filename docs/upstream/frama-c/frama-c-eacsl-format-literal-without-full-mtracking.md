# E-ACSL `--validate-format-strings` without `-M`: every format call aborts with "invalid format string"

Draft for the Frama-C tracker (https://git.frama-c.com/pub/frama-c/-/issues). **Filed on 2026-11-18 as [#2821](https://git.frama-c.com/pub/frama-c/-/work_items/2821), with merge request [!51](https://git.frama-c.com/pub/frama-c/-/merge_requests/51).** Number 33
in this folder's [index](./README.md). Found while preparing Issues 30 and 31, which use `-M` to get
past it.

## Summary

Without `-M` (`--full-mtracking`, `-e-acsl-full-mtracking`), a program built with
`e-acsl-gcc --validate-format-strings` aborts at its first call to a format function, whatever the
format:

```text
snprintf: invalid format string (unallocated or unterminated)
Aborted
```

for `snprintf(t, sizeof t, "%u.%u.%u.%u", a, b, c, d)`, and the same for `printf("lit %d\n", 1)`.
`"%s"` arguments that are local arrays, pointers to them or formals fail the same way. This
includes the example of the E-ACSL user manual (section "Format String Vulnerabilities",
`provides.tex`), which is documented without `-M` with the output
`printf: directive 1 ('%d') expects argument of type 'int' but the corresponding argument has type 'char*'`
and gives the "invalid format string" message instead.

## Verdict: a bug, known to the maintainers, not on the public tracker

- Upstream knows the symptom: both `tests/format/test_config_dev` and `tests/builtin/test_config_dev`
  pass `--full-mtracking` with `COMMENT: Remove --full-mtracking once e-acsl#118 is fixed`. The
  `frama-c/e-acsl` project is not readable (`glab api projects/frama-c%2Fe-acsl/issues/118`:
  `404 Project Not Found`), so I cannot see what #118 says or whether it covers format functions
  as well as the libc replacements.
- It is not documented behaviour: the manual does not say `--validate-format-strings` needs `-M`,
  and its example contradicts it. The "Maximized Memory Tracking" section only says the static
  analysis that reduces instrumentation "is probably the less robust part" of E-ACSL.
- No public issue or merge request: searched on 2026-11-17 for `full-mtracking`, `mtracking`,
  `string literal`, `format string`, `validate-format`, `printf` and `e-acsl#118` (issues and MRs,
  all states); the `mtracking` and `string literal` hits are this folder's #2794, #2795, #2804 and
  !26, !33, !35, about other things.

So it is worth a public issue, framed as "the public face of e-acsl#118", with the fix offered.

## Versions

| | Result |
|---|---|
| `34.0~beta (Selenium)`, image `framac-analysis:latest` (2026-11-17) | **aborts** |
| `master` `95408044f7`, image `framac-master-audit:9540804` | **aborts**, same output |
| `master` `95408044f7` + the patch | prints `192.168.1.200`, exit 0 |

Debian 13, gcc 14.2.0. (`-G clang` does not build the runtime under `--validate-format-strings`:
#2810.)

## Reproduction

[`./repro/33-eacsl-format-literal-without-full-mtracking.c`](./repro/33-eacsl-format-literal-without-full-mtracking.c):

```c
#include <stdio.h>

int main(void) {
  unsigned a = 192, b = 168, c = 1, d = 200;
  char t[16];
  snprintf(t, sizeof t, "%u.%u.%u.%u", a, b, c, d);
  return puts(t) < 0;
}
```

```text
$ e-acsl-gcc -q -c -G gcc --validate-format-strings -o m.c -O m ip.c && ./m.e-acsl; echo rc=$?
snprintf: invalid format string (unallocated or unterminated)
Aborted
rc=134
```

(`unsigned` arguments, so Issue 30 plays no part.) The script
[`./repro/33-eacsl-format-literal-without-full-mtracking.sh`](./repro/33-eacsl-format-literal-without-full-mtracking.sh)
adds seven cases (local array, pointer to it, formal, `"%n"`, the manual's example, and two
unterminated buffers that must abort), built with and without `-M`; on `master` all seven abort
with "invalid format string" without `-M`, and with `-M` give the expected results.

## Root cause

- `validate_format` (`share/e-acsl/libc_replacements/e_acsl_stdio.c`) starts with
  `valid_string(fmt)`, and the `"%s"`, `"%p"` and `"%n"` checks use `valid_nstring`, `allocated`
  and `writeable`: all need the block to be in the shadow memory.
- Which blocks are recorded is decided by the backward dataflow analysis in
  `src/analyses/memory_tracking.ml` unless `-e-acsl-full-mtracking` is set (`must_monitor_vi`
  short-circuits on it). For a call to a function without a body, `do_call` only has a case for
  `Functions.Libc.has_replacement` names (`strcpy`, `memcpy`, ...): it forces the string literals
  among the arguments to be monitored. Format functions (`Functions.Libc.is_printf_name`), which
  `injector.ml` replaces by `__e_acsl_builtin_printf` and friends when
  `Options.Validate_format_strings` is set, get nothing: neither the format literal nor a local
  array passed for `"%s"` is monitored, and the runtime's checks fail on them.

## Proposed fix

Patch [`./patches/33-eacsl-format-literal-without-full-mtracking.patch`](./patches/33-eacsl-format-literal-without-full-mtracking.patch),
14 lines of OCaml in `do_call`: when `Options.Validate_format_strings.get ()` and the callee is a
format function, add the base variable of every pointer or array argument to the set of monitored
variables (`Varinfos.add` also demotes string literals so that they get a block). This is the same
rule the analysis applies to the actuals of a function whose formals must be monitored, and it
propagates backwards through assignments: a `"%s"` argument that is a pointer to a local array, or a
formal, makes the array monitored.

Alternative for the maintainers: make `--validate-format-strings` imply `-e-acsl-full-mtracking`,
as `-e-acsl-concurrency` does (`options.ml`). Simpler, but costs the static analysis for the whole
program. The `builtin/` suite carries the same `e-acsl#118` comment for `--libc-replacements`;
that part (non-literal arguments of `strcpy` and friends) is not touched here and not analysed.

Cost of the patch: `format/test_config` (the default configuration) has no
`-e-acsl-full-mtracking`, so the generated-code oracles of `printf.c`, `fprintf.c` and `sprintf.c`
change (`git show --numstat`: `gen_printf.0.c` +3297/-547, `gen_fprintf.0.c` +594/-289,
`gen_sprintf.0.c` +34/-3; literal strings and locals now get `__e_acsl_store_block`,
`__e_acsl_full_init`, `__e_acsl_mark_readonly` and `__e_acsl_delete_block`). The `.res.oracle` files do not change. With `-M`, the instrumented code of
the three tests is byte-identical before and after (checked with `cmp` on the `e-acsl-gcc -M`
output), so the `dev` oracles cannot change.

## Validation (`master` `95408044f7`, 2026-11-17)

Same container as Issue 32 (`framac-master-audit:9540804`, dune build of the clone, installed).

- **Reproducer** before/after: outputs in the script header; 34.0~beta gives the `master` output.
  More probes without `-M` on the patched build: a struct field, `"%p"`, a heap string, a global
  format and global array, `argv`, all run; unterminated arrays passed directly, through a pointer
  or a formal all abort with `unterminated string in directive 1 ('%s')`. On the 30+31+32+33
  install, also without `-M`: a literal passed to a formal (`show("abc")`) and a global
  `const char *g = "abc"` passed for `"%s"` run.
- **New test** `tests/format/printf_mtracking.c` (12 sub-tests, 4 expected aborts), whose `dev`
  part overrides `ROOT_EACSL_GCC_OPTS_EXT` to drop `--full-mtracking`. On `master`: the default
  configuration differs (`gen_printf_mtracking.0.c` gains the `__e_acsl_store_block` of the
  literals, `t`, `s`, ...) and the `dev` run aborts before its first report, because the test
  harness's own `fprintf` fails too (`fprintf: invalid format string (unallocated or unterminated)`,
  `Expected exit code 0, got 134`). With the patch both pass.
- **ptests:** default `format/` (4 tests, after promoting the three changed oracles): exit 0.
  `dev`: `printf_mtracking.diff` and `fprintf.diff`, exit 0. Not run: `dev` of `printf.c` (reserved
  for 30/31; its instrumented code is identical, see above) and `sprintf.c`; other directories
  (only `format/` uses `--validate-format-strings`).
- **Lint:** `./dev/check-files.sh -p HEAD~1`: exit 0 (`Lint 8 file(s)`, ocp-indent on the `.ml`).
- **With 30, 31 and 32:** applies with `git am --3way --keep-non-patch` in the orders 33; 33 32;
  32 33; 30 31 32 33; 33 30 31 32; 31 33 30 32. On the four-patch tree, the `dev` runs of the four
  new tests and `fprintf.c` pass, but the default configuration fails on
  `gen_printf_fp_args.0.c`, `gen_printf_promoted.0.c` and `gen_printf_star.0.c`: their oracles were
  generated without this patch and gain the same monitoring code (in `gen_printf_star.0.c`: 36
  `__e_acsl_store_block` / `__e_acsl_full_init` / `__e_acsl_mark_readonly` / `__e_acsl_delete_block`
  each, 15 new literal globals). Whichever lands second has to regenerate those oracles
  (`dune promote`); the same holds for any other new `format/` test.
- **With 04, 13 and 26** (other patches of this folder touching `memory_tracking.ml` or
  `gen_printf.0.c`): `git am --3way` applies in the orders 04 33, 33 04, 13 33, 33 13, 26 33, 33 26
  and 04 13 26 33. Not built or tested together: the merged `gen_printf.0.c` may need regenerating.

## Filing package

- Issue: [`./filing/33-eacsl-format-literal-without-full-mtracking-issue.md`](./filing/33-eacsl-format-literal-without-full-mtracking-issue.md)
- MR: [`./filing/33-eacsl-format-literal-without-full-mtracking-mr.md`](./filing/33-eacsl-format-literal-without-full-mtracking-mr.md)
- Patch: [`./patches/33-eacsl-format-literal-without-full-mtracking.patch`](./patches/33-eacsl-format-literal-without-full-mtracking.patch)
- Repro: [`./repro/33-eacsl-format-literal-without-full-mtracking.sh`](./repro/33-eacsl-format-literal-without-full-mtracking.sh)
  with `33-eacsl-format-literal-without-full-mtracking.c` and `-cases.c`

## Open questions for the owner

- File it given that the maintainers track it privately as e-acsl#118? The issue text says so and
  asks whether they prefer the "imply full tracking" option.
- The oracle churn (about 4800 generated lines) makes this MR the one to land last among 30 to 33,
  or the others regenerate their `gen_*.0.c`.
