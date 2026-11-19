# MetAcsl: `\result` is refused in a `\postcond` property

Draft for the **MetAcsl** issue tracker (https://git.frama-c.com/pub/meta/-/issues, project id
869), not for `pub/frama-c`. **Not filed.** Issue 45 of this folder, drafted on 2026-11-18 on the
owner's instruction ("Draft upstream report, but don't fill it, update main discussion"; "fill"
read as "file"). The finding is listed in the overview issue #2832 since the same day (see
[Filing](#filing)).

**Package:**
[issue text](./filing/45-metacsl-result-in-postcond-issue.md),
[reproducer](./repro/45-metacsl-result-in-postcond.sh) with its
[C file](./repro/45-metacsl-result-in-postcond.c). There is no MR text and no file under
`patches/`: the patch below was never built.

## Summary

A MetAcsl property with `\context(\postcond)` becomes an `ensures` clause of each target, but
its predicate cannot use `\result`: MetAcsl stops with `\result meaningless`. Under `\tguard`
the same predicate becomes `\true`, which is the documented behaviour of `\tguard` and makes a
false property provable.

## Where the pipeline meets it

Layer 4 has a property "the gate leaves the auth state unchanged when it fails". It cannot be a
`\postcond` property, so `security_props.py` emits it as an in-code `check` before each return of
the gate (`code_checks`, `gate_failure`). The probe that led to this draft is item 5 of package R
of `docs/plans/metacsl-exploitation-plan.md` (on the branch `metacsl-integ` until it is merged). The
in-code check stays whatever upstream answers.

## Evidence

Run on 2026-11-18 in `framac-analysis:latest` (Frama-C 34.0~beta, MetAcsl 0.12~beta), with
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

- **Not run on `master`.** MetAcsl `master` is `4d5d0e91` (2026-10-15). Its `meta_parse.ml` has
  the git blob id `1dd7f37590a6`, the same as the file installed in the image, so the typing
  environment is built the same way. The audit image's MetAcsl plug-in does not load.
- **Tracker.** `pub/meta` had three issues on 2026-11-18 (1 and 3 closed, 4 open); none is about
  `\result`.

## Cause

- The kernel types `\result` with a lookup of the variable `\result` in the logic environment
  and reports `\result meaningless` when it is absent (`logic_typing.ml`, the `PLresult` case,
  line 3054 of the installed 34.0~beta sources).
- `process_meta_termassoc` in `meta_parse.ml` (lines 177 to 192 of the installed file) builds
  the environment of every property from `append_here_label`, `append_pre_label` and
  `append_old_and_post_labels`. Nothing calls `Logic_typing.add_result`.

## Draft patch (never built)

Written by hand from the installed sources; the line numbers are approximate. A build was
attempted in a throwaway container by a subagent and refused by the session's permissions; it
was not retried.

```diff
--- a/meta_parse.ml
+++ b/meta_parse.ml
@@ -177,16 +177,26 @@
 (* Given an association table, combine the previous functions to type
  * a full custom predicate
  *)
-let process_meta_termassoc typing_context loc kf termassoc expr =
+let process_meta_termassoc ?(with_result=false) typing_context loc kf termassoc expr =
   let quantifiers = Str_Hashtbl.create 5 in
   let meta_tc =
     {typing_context with
        type_predicate = (meta_type_predicate loc typing_context);
        type_term = (meta_type_term termassoc quantifiers kf loc typing_context)
     }
   in
   let fenv = Logic_typing.append_here_label meta_tc.pre_state in
   let fenv2 = Logic_typing.append_pre_label fenv in
   let fenv3 = Logic_typing.append_old_and_post_labels fenv2 in
-  let pred = meta_tc.type_predicate meta_tc fenv3 expr in
+  (* \result only has a meaning in a \postcond property, which becomes an ensures clause of [kf].
+     add_result does nothing for a function returning void. *)
+  let fenv4 =
+    if with_result then
+      let rt = Kernel_function.get_return_type kf in
+      Logic_typing.add_result fenv3 (Ctype (Ast_types.C.remove_qualifiers_deep rt))
+    else fenv3
+  in
+  let pred = meta_tc.type_predicate meta_tc fenv4 expr in
   Meta_bindings.after_parse meta_tc pred quantifiers
@@ -254,7 +264,7 @@
-let delay_prop tc name lexpr kf aslist =
+let delay_prop ?(with_result=false) tc name lexpr kf aslist =
   let dfind_var ?label:_ var =
@@ -276,7 +286,7 @@
   delayed_tc.on_error
-    (process_meta_termassoc delayed_tc loc kf aslist)
+    (process_meta_termassoc ~with_result delayed_tc loc kf aslist)
     (typing_error loc name (Kernel_function.get_name kf) aslist)
     lexpr
@@ -545,7 +555,8 @@
     (* Delegate typing of property *)
-    let mp_property = delay_prop tc mp_name expanded in
+    let mp_property =
+      delay_prop ~with_result:(mp_context = Postcond) tc mp_name expanded in
     let mp_used_meta_vars = extract_meta_vars expanded in
```

To check before it is proposed:

1. `dune build @install` against Frama-C 34 and against `master`.
2. The reproducer must print `plain: 3 / 3 proved` and `plain_violated: 2 / 3 proved`.
3. `\conditional_invariant` with `\result` and a `void` target must still be refused.
4. A property with `\flags(proof:deduce)` and `\result`: `meta_deduce.ml` types patterns with a
   dummy kernel function that returns `void`, so it must be guarded or it stops as today.
5. MetAcsl's own test suite, with a new test holding `\result` in a `\postcond`.

## Filing

- Target: `pub/meta`. [`../../../tools/upstream_audit/file_upstream.py`](../../../tools/upstream_audit/file_upstream.py)
  files on `pub/frama-c` (project 780) only, so this one is filed by hand or after the tool
  learns a project option.
- Filing is paused until the maintainers answer #2832. The overview issue and its local copy
  ([`./filing/00-reports-overview-issue.md`](./filing/00-reports-overview-issue.md)) got a line
  for this finding on 2026-11-18 (reference 45 in the annex, under MetAcsl).
