# [meta] allow \result in \postcond properties

- Source branch: `fix/meta-result-in-postcond` on the fork of `pub/meta`; target branch `master`.
- Based on: `4f43801390`. Patch: [`../patches/45-metacsl-result-in-postcond.patch`](../patches/45-metacsl-result-in-postcond.patch)
- `pub/meta` has no merge request template (no `.gitlab/` directory at `4f43801390`), so the
  description has no contribution checkboxes.

<!-- Everything below this line is the merge request description. Tracker: pub/meta (MetAcsl), not pub/frama-c. -->

Closes #<issue>.

## Problem

A meta-property with `\context(\postcond)` is translated into an `ensures` clause of each target
function, but `process_meta_termassoc` in `meta_parse.ml` built the logic typing environment from
`append_here_label`, `append_pre_label` and `append_old_and_post_labels` only, without calling
`Logic_typing.add_result`. Any `\postcond` predicate mentioning `\result` was therefore refused
with `\result meaningless` (and under `\tguard`, silently collapsed to `ensures ...: meta: \true;`,
making a false property provable).

## Change

- `meta_parse.ml`:
  - Thread an optional `?(with_result=false)` flag from `process_property` (set only when
    `mp_context = Postcond`) through `delay_prop` to `process_meta_termassoc`.
  - When `with_result` is true and `Ast_types.C.is_fun (Kernel_function.get_type kf)` holds, extend
    the typing environment with `Logic_typing.add_result fenv3 (Ctype rt)`, where `rt` is
    `Kernel_function.get_return_type kf` with `Ast_types.C.add_ghost rt` when
    `Kernel_function.is_ghost kf` (matching `Logic_typing.funspec` and `Filecheck.check_ast`).
  - Keeping `rt` without stripping inner qualifiers preserves pointed-to qualifiers (such as
    `const int *`) and typedef names so `-check` (`Cil_datatype.TypNoUnroll.equal` in
    `Filecheck`) and `\assert_type((const int *) \result)` succeed; `cabs2cil` already strips
    top-level qualifiers on C function return types.
  - Guarding on `Ast_types.C.is_fun` avoids calling `Kernel_function.get_return_type` on
    `Cil_datatype.Kf.dummy` (used by `Meta_deduce.dummy_unpack`, whose type is `Typ.dummy` rather
    than a `TFun`), which would otherwise abort with `Kernel.fatal "getReturnType: not a function
    type"` on every `\postcond` property during deduction (including `tests/meta-deduce/negative_assigns.c`
    and `deduction_with_offset.c`).
  - `Logic_typing.add_result` is a no-op for `void` return types, so `void`-returning targets stay
    refused with `\result meaningless` (and collapse to `\true` / `\false` under `\tguard` /
    `\fguard`).
  - All other contexts (`\precond`, `\weak_invariant`, `\strong_invariant`,
    `\conditional_invariant`, `\writing`, `\reading`, `\calling`) keep `with_result = false` and
    continue to refuse `\result`.
- `README.md` (`\postcond` context) and `CHANGELOG.md` (`# Version dev`): document `\result` in
  `\postcond`.
- New regression test `tests/meta/postcond_result.c` with its ten oracles (`oracle/` and
  `oracle_fold/`, `.0` through `.4`):
  - `.0` (exit 0): `\result` in `\postcond` for `int` (with `\old`), `const int`, `typedef int`,
    `const int *` (with `\assert_type((const int *) \result)`), `struct` (field accesses),
    `ghost int`, and `void` + `int` under `\tguard` / `\fguard`;
  - `.1` through `.4` (`EXIT: 1`): unguarded `\result` on a `void` target and in `\precond`,
    `\conditional_invariant` and `\writing` all refused with `\result meaningless`.

## Testing

On `4f43801390` built against Frama-C 34.0~beta (Debian 13, OCaml 5.5 switch). `master` does not
build against 34.0~beta as it is, so both builds below temporarily remove the one
`PLpointer_comparable` case of `meta_parse.ml` (not part of the patch); nothing else differs.

- **Reproducer from the issue (`login` with `\result != 0 ==> auth_ok == \old(auth_ok)`):**
  - Before (stock 0.12~beta and unpatched `master`): `plain` and `plain_violated` refused with
    `\result meaningless`; `guarded_violated` becomes `ensures \true` and WP proves 3 / 3 goals.
  - After: `plain` gives `3 / 3 proved`, `plain_violated` gives `2 / 3 proved`, `guarded_violated`
    gives `2 / 3 proved` (matching the hand-written `ensures` clause), `-check` passes, the printed
    code re-parses cleanly with `frama-c -check`, and the same holds with `-meta-no-simpl`,
    `-meta-fold`, `-meta-separate-annots` and `-then-last -e-acsl`.
- **Edge cases verified:**
  - `void`-returning targets: unguarded `\result` refused with `\result meaningless`; `\tguard`
    collapses to `ensures ...: meta: \true;` and `\fguard` to `ensures ...: meta: \false;`.
  - All seven non-`\postcond` contexts (`\precond`, `\weak_invariant`, `\strong_invariant`,
    `\conditional_invariant`, `\writing`, `\reading`, `\calling`): every one refused with
    `\result meaningless`.
  - Non-`int` return types (`const int`, `typedef int`, `typedef const int`, `int *`,
    `const int *`, `int * const`, `typedef const int *`, `struct`, `const struct`, `ghost int`),
    combined with `\formal`, `\macro`, `\at(..., Post)` and `\assert_type`: all pass `-check`,
    re-parse cleanly and run through WP identically in default and `-meta-fold` modes.
  - `-meta-fold`: `weak_inv_visitor#add_to_contract` does not fold contract clauses, so `\postcond`
    with `\result` emits the exact same `ensures` clause under `-meta-fold` and passes `-check`,
    re-parse, WP and E-ACSL.
  - `meta_deduce`: existing `tests/meta-deduce` tests (`negative_assigns.c`,
    `deduction_with_offset.c`, `consequence.c`) produce output byte-for-byte identical to unpatched
    `master` (no `getReturnType` fatal error). A `\postcond` using unguarded `\result` with
    `\flags(proof:deduce)` (or preceding another `proof:deduce` property) stops during
    `dummy_unpack` with `Where: in function '@dummy_varinfo@', Why: \result meaningless`, matching
    existing behavior for unguarded `\formal(...)`; under `\tguard`, `dummy_unpack` evaluates it
    to `\true`, matching existing guarded behavior.
- **Suites `tests/meta` and `tests/meta-wp`, default and `fold` configurations:** `dune build
  @tests/meta/ptests` could not run in my environment (a `(package frama-c)` dependency on
  documentation files the installation does not ship), so I ran every command `frama-c-ptests`
  generated for `tests/meta` and `tests/meta-wp` in both configurations and compared the logs with
  the oracles and with unpatched `master` (built the same way):
  - with the patch: `tests/meta` 26 of 26 pass in default and 26 of 26 in `fold` (empty stderr);
    `tests/meta-wp` 12 of 12 pass in default and 12 of 12 in `fold` (empty stderr);
  - without the patch (with `postcond_result.c` copied in): all 21 + 21 existing `tests/meta` runs
    and 12 + 12 `tests/meta-wp` runs are byte-for-byte identical to the patched build (0 diffs),
    while `postcond_result.0` fails with exit code 1 (`\result meaningless` on
    `unchanged_on_failure`) and `.1` / `.3` abort early on `unchanged_on_failure`;
  - the printed `.0` output of `postcond_result.c` also re-parses cleanly with `frama-c -check`,
    and WP proves 23 of 24 goals (all except the intentional `res_fguard: \false` on `do_void`).
- **Headers:** `tests/**`, `README.md` and `CHANGELOG.md` are `header_spec=.ignore` in
  `.gitattributes`, so the new files carry no header. Like the existing oracles, the `.0` oracles
  end with an empty line.
- **Not run:** SWI-Prolog deduction proofs in `tests/meta-deduce` (SWI-Prolog not installed),
  `ocp-indent` / header checks, and a build against the kernel's `master`.

The analysis and fix were prepared with LLM assistance; I reviewed them and ran the reproducer
and tests described above.
