# MetAcsl: `\result` is refused in a `\postcond` property

Draft for the **MetAcsl** issue tracker (https://git.frama-c.com/pub/meta/-/issues, project id
869), not for `pub/frama-c`. **Not filed.** Issue 45 of this folder, drafted on 2026-11-18 on the
owner's instruction ("Draft upstream report, but don't fill it, update main discussion"; "fill"
read as "file"), with a validated patch and MR text built on 2026-11-20. The finding is listed in
the overview issue #2832 since 2026-11-18 (see [Filing](#filing)).

**Package:**
[issue text](./filing/45-metacsl-result-in-postcond-issue.md),
[MR text](./filing/45-metacsl-result-in-postcond-mr.md),
[patch](./patches/45-metacsl-result-in-postcond.patch),
[reproducer](./repro/45-metacsl-result-in-postcond.sh) with its
[C file](./repro/45-metacsl-result-in-postcond.c).

## Summary

A MetAcsl property with `\context(\postcond)` becomes an `ensures` clause of each target, but
its predicate cannot use `\result`: MetAcsl stops with `\result meaningless`. Under `\tguard`
the same predicate becomes `\true`, which is the documented behaviour of `\tguard` and makes a
false property provable.

## Where the pipeline meets it

Layer 4 has a property "the gate leaves the auth state unchanged when it fails". It cannot be a
`\postcond` property, so `security_props.py` emits it as an in-code `check` before each return of
the gate (`code_checks`, `gate_failure`). The probe that led to this draft is item 5 of package R
of [`../../plans/metacsl-exploitation-plan.md`](../../plans/metacsl-exploitation-plan.md). The
in-code check stays whatever upstream answers.

## Evidence

Run in `framac-analysis:latest` (Frama-C 34.0~beta, MetAcsl 0.12~beta, and unpatched `pub/meta`
`master` `4f43801390` built against the installed 34.0~beta kernel), with
[`./repro/45-metacsl-result-in-postcond.sh`](./repro/45-metacsl-result-in-postcond.sh):

```
34.0~beta (Selenium)
plain: refused: \result meaningless
plain_violated: refused: \result meaningless
guarded_violated: ensures \true, 3 / 3 proved
by_hand: 3 / 3 proved
by_hand_violated: 2 / 3 proved
RESULT: \result is refused in \postcond (2 of 2 cases)
```

- **MetAcsl `master`** (`4f43801390`, built against the installed 34.0~beta kernel, see
  [Validation](#validation)) gives the exact same "before" output as installed 0.12~beta.
- **Tracker.** `pub/meta` had three issues (#1 and #3 closed, #4 open); none is about `\result`.

## Cause

- The kernel types `\result` with a lookup of the variable `\result` in the logic environment
  and reports `\result meaningless` when it is absent (`logic_typing.ml`, the `PLresult` case,
  line 3044 of the installed 34.0~beta sources).
- `process_meta_termassoc` in `meta_parse.ml` (lines 180 to 192 on `master`) builds the environment
  of every property from `append_here_label`, `append_pre_label` and `append_old_and_post_labels`.
  Nothing calls `Logic_typing.add_result`.

## Fix

Thread an optional `?(with_result=false)` flag from `process_property` (set only when
`mp_context = Postcond`) through `delay_prop` to `process_meta_termassoc` in `meta_parse.ml`:

```ocaml
  (* \result only has a meaning in a \postcond property, which becomes an
     ensures clause of [kf]. Guard on [is_fun] because [Meta_deduce.dummy_unpack]
     types properties with [Cil_datatype.Kf.dummy], whose type is [Typ.dummy]
     rather than a function type. [add_result] leaves the environment unchanged
     when [kf] returns void. *)
  let fenv4 =
    if with_result && Ast_types.C.is_fun (Kernel_function.get_type kf) then
      let rt = Kernel_function.get_return_type kf in
      let rt =
        if Kernel_function.is_ghost kf then Ast_types.C.add_ghost rt else rt
      in
      Logic_typing.add_result fenv3 (Ctype rt)
    else fenv3
  in
```

Three refinements compared to the original unbuilt 2026-11-18 hand-written draft (each verified
empirically by reproducing the failure of the unbuilt draft before fixing it):

1. **Do not call `Ast_types.C.remove_qualifiers_deep` on `rt`.** `cabs2cil` already strips
   top-level qualifiers on C function return types (`const int` becomes `int`, `int * const`
   becomes `int *`), while keeping pointed-to qualifiers (`const int *` stays `int const *`).
   `Logic_typing.funspec` (line 3934) passes `Cil.getReturnType` directly, and `Filecheck`
   (`filecheck.ml:778`) checks `Cil_datatype.TypNoUnroll.equal t t1` against
   `Kernel_function.get_return_type kf`. With `remove_qualifiers_deep`, a function returning
   `const int *` aborts `-check` (exit 4: `\result of type int * found in a contract for function
   f that returns int const *`) and breaks `\assert_type((const int *) \result)`.
2. **Recover `ghost` for ghost functions (`Kernel_function.is_ghost kf`).** Both
   `Logic_typing.funspec` (`logic_typing.ml:3936`) and `Filecheck` (`filecheck.ml:771`) apply
   `Ast_types.C.add_ghost` when the function is ghost. Without it, a `\postcond` using `\result`
   on a `ghost` function aborts `-check` (exit 4: `\result of type int found in a contract for
   function g that returns int \ghost`).
3. **Guard on `Ast_types.C.is_fun (Kernel_function.get_type kf)`.** `Meta_deduce.dummy_unpack`
   (`meta_deduce.ml:165`) types properties with `Cil_datatype.Kf.dummy`, whose `svar.vtype` is
   `Cil_datatype.Typ.dummy` (`TVoid []`, not a `TFun`), rather than a `void(void)` function type.
   Without the `is_fun` guard, `Kernel_function.get_return_type Cil_datatype.Kf.dummy` crashes with
   `Kernel.fatal: getReturnType: not a function type` (exit 4) on **every** `\postcond` property
   during deduction — even properties that do not use `\result` at all, such as upstream's
   `tests/meta-deduce/negative_assigns.c` and `tests/meta-deduce/deduction_with_offset.c`.

The patch (`26` insertions / `4` deletions in `meta_parse.ml`, a `README.md` note under
`\postcond`, a `CHANGELOG.md` bullet under `# Version dev`, and `tests/meta/postcond_result.c`
with ten oracles across `oracle/` and `oracle_fold/`) keeps all `tests/**` files header-free per
`.gitattributes` (`header_spec=.ignore`).

### Validation

Built on 2026-11-20 in a throwaway `framac-analysis:latest` container: `dune build @install` of
`pub/meta` `master` (`4f43801390`) with and without the patch, both with only the single
post-34.0~beta `PLpointer_comparable` line in `meta_parse.ml` removed for the container build (that
removal is not in the exported patch). The built `MetAcsl.cmxs` replaced the installed one.

- **Reproducer before and after the patch:**
  - Before (stock 0.12~beta and unpatched `master` `4f43801390`): exit 1
    (`RESULT: \result is refused in \postcond (2 of 2 cases)`).
  - After (exit 0):

    ```
    34.0~beta (Selenium)
    plain: 3 / 3 proved
    plain_violated: 2 / 3 proved
    guarded_violated: 2 / 3 proved
    by_hand: 3 / 3 proved
    by_hand_violated: 2 / 3 proved
    RESULT: \result is accepted in \postcond
    ```

  - Note that `guarded_violated` also changes from `ensures \true, 3 / 3 proved` to `2 / 3 proved`,
    because `\result` now types cleanly inside `\tguard` instead of falling back to `\true`.
  - `-check`, re-parsing the printed C code with `frama-c -check`, and WP (`3 / 3` on `plain`,
    `2 / 3` on `plain_violated`) all pass under default mode (`-meta`, with simplification),
    `-meta-no-simpl`, `-meta-fold`, `-meta-fold -meta-no-simpl`, and `-meta-separate-annots`.
    E-ACSL (`-then-last -e-acsl`) also succeeds in both default and `-meta-fold` modes.

- **Edge cases:**
  - **`void`-returning targets:** unguarded `\result == 0` in `\postcond` is refused with
    `\result meaningless` (exit 1); `\tguard(\result == 0)` collapses to `ensures ...: meta: \true;`
    and `\fguard(\result == 0)` to `ensures ...: meta: \false;`, passing `-check` and re-parse.
  - **All seven non-`\postcond` contexts:** `\precond`, `\weak_invariant`, `\strong_invariant`,
    `\conditional_invariant`, `\writing`, `\reading` and `\calling` with `\result == 0` are every
    one refused with `\result meaningless` (exit 1).
  - **Non-`int` return types:** tested `int`, `const int`, `typedef int`, `typedef const int`,
    `int *`, `const int *`, `int * const`, `typedef const int *`, `struct S { int x; const int y; }`,
    `const struct S`, and `/*@ ghost int ... */`, combined with `\formal`, `\macro`,
    `\at(*\result, Post)` and `\assert_type((const int *) \result)`. All pass `-check`, re-parse
    cleanly and run through WP identically in default and `-meta-fold` modes.
  - **`-meta-fold` interaction:** `weak_inv_visitor#add_to_contract` (`meta_annotate.ml:439`) does
    not call `create_instance` — MetAcsl never folds contract clauses (`\postcond`, `\precond`,
    `\weak_invariant`, `\conditional_invariant`), only statement annotations. Under `-meta-fold`,
    `\postcond` with `\result` emits the exact same `ensures` clause as default mode and passes
    `-check`, re-parse, WP and E-ACSL. (In `tests/meta/postcond_result.c`, sub-test `.4` for
    `\writing` does go through `create_folded_predicate` under `-meta-fold`, so its error message
    lists `Environment: there were no meta-variables.` in `oracle_fold/` vs the unfolded meta-vars
    in `oracle/`; both abort with `Why: \result meaningless`.)
  - **`meta_deduce` interaction (`\flags(proof:deduce)`):**
    - Existing `tests/meta-deduce` (`negative_assigns.c`, `deduction_with_offset.c`,
      `consequence.c`, default and `fold` configurations): 0 diffs between unpatched `master` and
      patched `master` (the `Ast_types.C.is_fun` guard avoids the `getReturnType` fatal crash on
      `Cil_datatype.Kf.dummy`).
    - A `\postcond` property using unguarded `\result` with `\flags(proof:deduce)` — or a
      `proof:local` `\postcond` with unguarded `\result` preceding another `proof:deduce` property
      in the same file — aborts during `Meta_deduce.dummy_unpack` with
      `Where: in function '@dummy_varinfo@', Why: \result meaningless` (the same behaviour as
      unguarded `\formal(...)` under `meta_deduce`, because `dummy_unpack` has no target return
      type). Under `\tguard`, `dummy_unpack` evaluates the guarded predicate to `\true` (emitting
      `property({},p1)` in the `.slog` file, matching existing guarded behavior for `\formal` and
      struct-dereferenced `\written`).

- **MetAcsl suites `tests/meta` and `tests/meta-wp` (default and `fold` configurations):**
  `dune build @tests/meta/ptests` cannot run in the image (the `(package frama-c)` dependency asks
  for documentation files the image does not ship), so every command `frama-c-ptests` generated in
  `*.exec.wtests` for `tests/meta` and `tests/meta-wp` in both configurations was executed and
  compared against the oracles and against unpatched `master` (built the same way):
  - With the patch: `tests/meta` 26 of 26 pass in default and 26 of 26 in `fold` (empty stderr);
    `tests/meta-wp` 12 of 12 pass in default and 12 of 12 in `fold` (empty stderr).
  - Without the patch (with `postcond_result.c` copied in): all 21 + 21 existing `tests/meta` runs
    and 12 + 12 `tests/meta-wp` runs are byte-for-byte identical to the patched build (0 diffs
    across all 198 output/stderr/exit-code files), while `postcond_result.0` fails with exit code 1
    (`\result meaningless` on `unchanged_on_failure`) and `.1` / `.3` abort early on
    `unchanged_on_failure`.
  - Re-parsing the printed `.0` output of `postcond_result.c` passes `frama-c -check`, and WP
    proves 23 of 24 goals (all except the intentional `res_fguard: meta: \false` on `do_void`).

- **Patch application and stacking with 47, 48 and 49:**
  - Single patch on pristine `4f43801390`: `git apply --check` and `git am --keep-non-patch` both
    succeed cleanly (`git am` notes the two new blank lines at EOF of the `.0` oracles, as Frama-C
    prints them).
  - Stacked with `47`, `48` and `49` via `git am --keep-non-patch --3way` in both orders
    (`45, 47, 48, 49` and `47, 48, 49, 45`): `meta_parse.ml`, `meta_annotate.ml`, `README.md`,
    `meta_options.ml`/`.mli` and all test/oracle files merge cleanly; only the `# Version dev`
    section of `CHANGELOG.md` conflicts (the same conflict already noted for `47, 48, 49`). Built
    from the 4-patch stack, `tests/meta` passes 31 of 31 in default and 31 of 31 in `fold`,
    `tests/meta-wp` passes 12 of 12 in default and 12 of 12 in `fold`, and all four reproducers
    (45, 47, 48, 49) exit 0.

- **Not run:** SWI-Prolog deduction proofs in `tests/meta-deduce` (SWI-Prolog absent), MetAcsl's
  CI, `ocp-indent` / header checks, and a build against the kernel `master` targets.

## Filing

- Target: `pub/meta`. [`../../../tools/upstream_audit/file_upstream.py`](../../../tools/upstream_audit/file_upstream.py)
  files on `pub/frama-c` (project 780) only, so this one is filed by hand or after the tool
  learns a project option.
- Filing is paused until the maintainers answer #2832. No branch was pushed, no issue or merge
  request was created on `pub/meta`, and #2832 was not edited (the overview issue and its local
  copy [`./filing/00-reports-overview-issue.md`](./filing/00-reports-overview-issue.md) already
  list this finding since 2026-11-18 as reference 45 in the annex, under MetAcsl). The MR text
  holds `#<issue>`.
