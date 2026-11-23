# [kernel] validate positive type sizes and alignments in YAML machdeps

- Source branch: `fix/kernel-machdep-zero-size-crash` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `189053d4a2`. Patch: [`../patches/85-kernel-machdep-zero-size-crash.patch`](../patches/85-kernel-machdep-zero-size-crash.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #<issue>.

## Problem

`Machdep.mach_of_yaml` (`src/kernel/internals/runtime/machdep.ml:102`) did not validate that
concrete scalar/pointer type sizes and alignments are positive. Loading a custom YAML machdep with
`sizeof_int: 0` or `sizeof_long: -1` crashed Frama-C in `Machdep.max_val` (`machdep.ml:451`) with
`Unexpected error (Invalid_argument("Z.shift_left: count argument must be positive"))` (exit 125),
and `alignof_ptr: 0` was accepted silently.

## Change

`src/kernel/internals/runtime/machdep.ml` (lines 104-128):

- Add `validate_mach` checking that the 16 concrete scalar/pointer `sizeof_*` and `alignof_*` fields
  (`short`, `int`, `long`, `longlong`, `ptr`, `float`, `double`, `longdouble`) are strictly positive
  (`> 0`), and wrap `mach_of_yaml` with `Result.bind (mach_of_yaml y) validate_mach`.
- Leave sentinel-capable fields (`sizeof_void`, `sizeof_fun`, `alignof_void`, `alignof_fun`,
  `alignof_aligned`, `alignof_max_align_t`, `max_extended_alignment`, `gcc_alignof_*`) untouched so
  all shipped machdeps (including `machdep_msvc_x86_64.yaml` with `sizeof_void: 0` and
  `custom_machdep.yaml` with `sizeof_int: 3`) remain valid.
- `File.get_machdep` turns the returned `Error (`Msg ...)` directly into `[kernel] User Error: Error
  during machdep parsing: Field <name> must be strictly positive (got <v>)` (exit 1).

Extend Cram test `tests/misc/machdep.t/run.t` with three regression cases (`sizeof_int: 0`,
`sizeof_long: -1`, `alignof_ptr: 0`). No existing oracle changes.

## Testing

All on Debian 13 (OCaml 5.5, gcc 14.2.0), upstream `master` at `189053d4a2`:

- **Standalone reproducer (`sizeof_int_0`, `sizeof_long_neg`, `alignof_ptr_0`):**
  - Before (`master` `189053d4a2` and `34.0~beta`): `sizeof_int_0` and `sizeof_long_neg` crash with
    exit 125 (`Invalid_argument`), `alignof_ptr_0` exits 0 (`RESULT: bug present (3 of 3 cases
    fail)`).
  - After (installed patched `master`): all 3 cases exit 1 with `User Error: Error during machdep
    parsing: Field ... must be strictly positive` (`RESULT: fixed`).
- **New Cram test on unpatched `master`:** `dune runtest tests/misc/machdep.t` fails; passes with
  the patch.
- **ptests, default configuration:** `./dev/test.sh -p tests/misc -- -j 2` passes with zero diffs
  on any existing oracle.
- **`./dev/check-files.sh -p HEAD~1`:** passes (`Lint 2 file(s)`).
- **Not run:** suites outside `tests/misc` (all shipped machdeps satisfy the positivity check).

The analysis and fix were prepared with LLM assistance; I reviewed them and ran the reproducer and
tests described above.
