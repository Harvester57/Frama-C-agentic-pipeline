# E-ACSL: deprecated `-e-acsl-assert-print-data` is an alias of `-e-acsl-O-valid` instead of `-e-acsl-O-print-values`

Draft bug report for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).

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

- Reproduced with Frama-C `35.0~~dev (Bromine)`, built from `master` at `ad24dca` (2026-11-02).
- Same in `34.0~~dev (Selenium)`.

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

## Proposed fix

```diff
--- a/plugins/e-acsl/src/options.ml
+++ b/plugins/e-acsl/src/options.ml
@@ -209,7 +209,7 @@ module Optimisations = struct
       let descr = "print values of variables involved in a failed \
                    verification along with the runtime error message"
     end)
-  let () = Verify_valid.add_aliases ~deprecated:true ~visible:false
+  let () = Print_values.add_aliases ~deprecated:true ~visible:false
       ["-e-acsl-assert-print-data"]
 
   module Gmp_only = Make (struct
```

## Validation of the proposed fix

Built from `ad24dca` with the patch:

| Check | `master` | Patched |
|---|---|---|
| Deprecation warning for `-e-acsl-assert-print-data` | `… alias for option -e-acsl-O-valid` | `… alias for option -e-acsl-O-print-values` |
| Deprecation warning for `-e-acsl-no-assert-print-data` | `… alias for option -e-acsl-O-no-valid` | `… alias for option -e-acsl-O-no-print-values` |
| `__e_acsl_assert` count: default / with the alias / with `-e-acsl-O-valid` | 32 / 40 / 40 | 32 / 32 / 40 |
| ptests `plugins/e-acsl/tests` | — | no change |

## Workaround

Drop `-e-acsl-assert-print-data`. Values are printed by default; `-e-acsl-O-print-values` forces it.
