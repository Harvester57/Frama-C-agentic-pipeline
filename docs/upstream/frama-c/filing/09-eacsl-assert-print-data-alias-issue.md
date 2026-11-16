# [E-ACSL] Deprecated option -e-acsl-assert-print-data is an alias of -e-acsl-O-valid instead of -e-acsl-O-print-values

<!-- Everything below this line is the issue description. -->

### Summary

The deprecated option `-e-acsl-assert-print-data` is declared as an alias of `-e-acsl-O-valid` instead of `-e-acsl-O-print-values`, a copy-paste error in `options.ml`. Using it changes an unrelated optimisation and does not control the printing of data.

### Steps to reproduce the issue

`t.c`:

```c
int main(void) {
  int x = 1;
  /*@ assert x == 1; */
  return 0;
}
```

```sh
frama-c -machdep gcc_x86_64 t.c -e-acsl -e-acsl-assert-print-data
frama-c -machdep gcc_x86_64 t.c -e-acsl -e-acsl-no-assert-print-data

# Value printing: count the __e_acsl_assert_register_* calls (0 = off)
frama-c -machdep gcc_x86_64 t.c -e-acsl -e-acsl-O-no-print-values -then-last -print | grep -c __e_acsl_assert_register_
frama-c -machdep gcc_x86_64 t.c -e-acsl -e-acsl-no-assert-print-data -then-last -print | grep -c __e_acsl_assert_register_

# Proven annotations: WP proves the assertion, so E-ACSL skips it unless -e-acsl-O-valid
frama-c -machdep gcc_x86_64 t.c -wp -wp-prover qed -then -e-acsl -then-last -print | grep -c '__e_acsl_assert('
frama-c -machdep gcc_x86_64 t.c -wp -wp-prover qed -then -e-acsl -e-acsl-O-valid -then-last -print | grep -c '__e_acsl_assert('
frama-c -machdep gcc_x86_64 t.c -wp -wp-prover qed -then -e-acsl -e-acsl-assert-print-data -then-last -print | grep -c '__e_acsl_assert('
```

### Expected behaviour

`-e-acsl-assert-print-data` printed the values involved in a failed assertion, so its deprecated
alias should map to `-e-acsl-O-print-values` (as `e-acsl-gcc --assert-print-data` already does):

- the deprecation warnings name `-e-acsl-O-print-values` and `-e-acsl-O-no-print-values`;
- `-e-acsl-no-assert-print-data` turns value printing off (0 register calls, like
  `-e-acsl-O-no-print-values`);
- `-e-acsl-assert-print-data` does not re-instrument the proven assertion (0 calls, like the
  default).

### Actual behaviour

The alias is wired to `-e-acsl-O-valid`:

```text
[kernel] Warning: -e-acsl-assert-print-data is a deprecated alias for option -e-acsl-O-valid.
  Please use -e-acsl-O-valid instead.
[kernel] Warning: -e-acsl-no-assert-print-data is a deprecated alias
  for option -e-acsl-O-no-valid. Please use -e-acsl-O-no-valid instead.
```

| Option | `__e_acsl_assert_register_*` calls | `__e_acsl_assert(` calls after WP |
|---|---|---|
| (default) | 2 | 0 |
| `-e-acsl-O-no-print-values` | 0 | |
| `-e-acsl-no-assert-print-data` | **2** (values still printed) | |
| `-e-acsl-O-valid` | | 2 |
| `-e-acsl-assert-print-data` | | **2** (proven assertion re-instrumented) |

A script that still passes the old option gets slower binaries that re-check annotations other
analyses already proved, and the warning tells the user to switch to the wrong option.

**Cause.** `plugins/e-acsl/src/options.ml:212` (master `3dff90fc70`) registers the alias on the
wrong module, a copy-paste slip from the `-e-acsl-valid` alias registered on `Verify_valid` a few
lines above:

```ocaml
  module Print_values =
    Make (struct
      let name = "print-values"
      ...
    end)
  let () = Verify_valid.add_aliases ~deprecated:true ~visible:false
      ["-e-acsl-assert-print-data"]
```

**Fix.** `Print_values.add_aliases` instead of `Verify_valid.add_aliases`. A merge request with a fix
follows.

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at 3dff90fc70; also 34.0~beta (Selenium)
- Plug-in used: E-ACSL
- OS name: Debian GNU/Linux
- OS version: 13 (trixie)

### Additional information (optional)

Same output on 34.0~beta (Selenium) and on master `3dff90fc70`.

Workaround: drop `-e-acsl-assert-print-data` (values are printed by default up to `-e-acsl-O 3`)
and use `-e-acsl-O-no-print-values` instead of `-e-acsl-no-assert-print-data`.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
