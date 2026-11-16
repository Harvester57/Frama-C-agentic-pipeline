# E-ACSL: deprecated `-e-acsl-assert-print-data` is an alias of `-e-acsl-O-valid` instead of `-e-acsl-O-print-values`

**Filed upstream on 2026-11-15:** issue [#2808](https://git.frama-c.com/pub/frama-c/-/work_items/2808), merge request [!39](https://git.frama-c.com/pub/frama-c/-/merge_requests/39).

Draft bug report for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).

**Filing package:** [issue](./filing/09-eacsl-assert-print-data-alias-issue.md), [MR](./filing/09-eacsl-assert-print-data-alias-mr.md), [reproducer](./repro/09-eacsl-assert-print-data-alias.sh), [patch](./patches/09-eacsl-assert-print-data-alias.patch)

## Summary

The deprecated alias `-e-acsl-assert-print-data` is registered on the wrong option in
`plugins/e-acsl/src/options.ml:212`:

```ocaml
module Print_values =
  Make (struct
    let name = "print-values"
    let level = Leq 3
    let descr = "print values of variables involved in a failed \
                 verification along with the runtime error message"
  end)
let () = Verify_valid.add_aliases ~deprecated:true ~visible:false
    ["-e-acsl-assert-print-data"]
```

This looks like a copy-paste slip from the `-e-acsl-valid` alias a few lines above. The old option
printed the values involved in a failed assertion, which is what `-e-acsl-O-print-values` does. The
alias instead turns on `-e-acsl-O-valid`, which **re-instruments annotations that other analyses
have already proven valid**. Scripts that still pass the old flag therefore get slower binaries with
more checks, and the values are printed anyway (`print-values` is on by default at `-O ≤ 3`).

The kernel's deprecation warning states the wrong mapping, so users are told to switch to the wrong
option:

```text
[kernel] Warning: -e-acsl-no-assert-print-data is a deprecated alias
  for option -e-acsl-O-no-valid. Please use -e-acsl-O-no-valid instead.
```

## Versions

- Reproduced on 2026-11-15 with Frama-C `35.0~~dev (Bromine)`, `master` at `3dff90fc70`
  (2026-11-13), and with `34.0~beta (Selenium)`: same output on both
  ([reproducer](./repro/09-eacsl-assert-print-data-alias.sh)).
- First seen on `master` `ad24dca` (2026-11-02) and `34.0~~dev (Selenium)`.

## Reproduction

`valid_test.c`:

```c
int main(void) {
  int x = 1;
  /*@ assert x == 1; */
  return 0;
}
```

```text
$ frama-c valid_test.c -e-acsl -e-acsl-assert-print-data
[kernel] Warning: -e-acsl-assert-print-data is a deprecated alias for option -e-acsl-O-valid.

$ frama-c valid_test.c -wp -then -e-acsl -then-last -print | grep -c __e_acsl_assert
32
$ frama-c valid_test.c -wp -then -e-acsl -e-acsl-assert-print-data -then-last -print | grep -c __e_acsl_assert
40
$ frama-c valid_test.c -wp -then -e-acsl -e-acsl-O-valid -then-last -print | grep -c __e_acsl_assert
40
```

WP proves the assertion, so E-ACSL skips it by default (32 occurrences). With the deprecated flag,
it instruments it again, exactly like `-e-acsl-O-valid` (40).

## Fix (patch)

[`patches/09-eacsl-assert-print-data-alias.patch`](./patches/09-eacsl-assert-print-data-alias.patch),
one commit on `fix/eacsl-assert-print-data-alias` from `3dff90fc70`,
"[e-acsl] fix the target of deprecated alias -e-acsl-assert-print-data":

- `plugins/e-acsl/src/options.ml:212`: `Print_values.add_aliases` instead of
  `Verify_valid.add_aliases`.
- Regression test: `plugins/e-acsl/tests/special/e-acsl-no-assert-print-data.c` gets a second
  default-configuration run, `STDOPT: #"-e-acsl-no-assert-print-data"`. Its new `gen_*.1.c` oracle
  is identical to the `gen_*.0.c` of the `-e-acsl-O-no-print-values` run; on `master` it has two
  more lines (`__e_acsl_assert_register_int` and `__e_acsl_assert_clean`). The `.1.res.oracle`
  records the corrected warning. The run header keeps its line count, so the `.0` oracles do not
  change.
- `plugins/e-acsl/doc/Changelog`: one entry.

## Validation

Validated on 2026-11-15: patch built over `framac-master-audit:3dff90f` (master `3dff90fc70`) and
installed.

| Check | `master` `3dff90fc70` | Patched |
|---|---|---|
| Warning for `-e-acsl-assert-print-data` | `… alias for option -e-acsl-O-valid` | `… alias for option -e-acsl-O-print-values` |
| Warning for `-e-acsl-no-assert-print-data` | `… alias for option -e-acsl-O-no-valid` | `… alias for option -e-acsl-O-no-print-values` |
| `__e_acsl_assert_register_*` calls: default / `-e-acsl-O-no-print-values` / `-e-acsl-no-assert-print-data` | 2 / 0 / 2 | 2 / 0 / 0 |
| `__e_acsl_assert(` calls after WP: default / `-e-acsl-O-valid` / `-e-acsl-assert-print-data` | 0 / 2 / 2 | 0 / 2 / 0 |
| New run `special/e-acsl-no-assert-print-data.1` | `gen_*.1.c` differs from `gen_*.0.c` | identical |
| ptests `plugins/e-acsl/tests`, default configuration (198 results) | — | pass; only the two new oracles added |
| `34.0~beta (Selenium)` | same as `master` | — |

`git diff --check` is clean except for the generated oracles (trailing space after `Warning:`,
final empty line, as in every oracle). `clang-format-19 --dry-run` passes on the test file.
`make check-lint` / `make check-headers` were not run (no `ocp-indent` or `headache` in the image).
The E-ACSL `dev` configuration was not run for this patch: it goes through `e-acsl-gcc`, which maps
`--assert-print-data` to `-e-acsl-O-print-values` and never uses the deprecated alias.

## Workaround

Drop `-e-acsl-assert-print-data`. Values are printed by default; `-e-acsl-O-print-values` forces it.
