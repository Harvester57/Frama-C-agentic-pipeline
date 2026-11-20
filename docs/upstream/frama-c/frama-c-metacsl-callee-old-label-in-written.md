# MetAcsl: the `\written` / `\read` instances at a call keep the `Old`, `Pre` and `Here` labels of the callee's contract

Draft for the **MetAcsl** issue tracker (https://git.frama-c.com/pub/meta/-/issues, project id
869), not for `pub/frama-c`. **Not filed.** Issue 47 of this folder, drafted on 2026-11-20.

**Package:**
[issue text](./filing/47-metacsl-callee-old-label-in-written-issue.md),
[MR text](./filing/47-metacsl-callee-old-label-in-written-mr.md),
[patch](./patches/47-metacsl-callee-old-label-in-written.patch),
[reproducer](./repro/47-metacsl-callee-old-label-in-written.sh) with its
[C file](./repro/47-metacsl-callee-old-label-in-written.c).

## Summary

At a call to a function known only by its contract (an undefined callee, under the default
`-meta-check-ext`, or a function given to `-meta-check-callee-assigns`), MetAcsl checks a
`\writing` property on each assigns location of the callee. It replaces the formals by the actual
arguments and puts the result, as `\written`, in an assertion before the call. The labels of the
callee's contract are copied unchanged:

- **`Old`** comes from an explicit `\old(...)` in the assigns clause, or from the kernel, which
  gives `Old` to a labelled logic function called without a label in an assigns clause
  (`strlen(s)` becomes `strlen{Old}(s)`). `Old` is not allowed in a statement annotation (ACSL
  1.24, table 2.1: function and statement contracts only). `-check` stops in the AST integrity
  check (`Logic label Old is not declared in this scope`), the printed code does not re-parse
  (``logic label `Old' not found``), WP stops with `Unexpected error
  (Wp__NormAtLabels.LabelError(_))` and E-ACSL with `invalid label 'Old' within statement
  annotation 'Assertion'`.
- **`Pre`** is accepted by the kernel in the callee's contract, where it is the callee's
  pre-state, and is allowed in a statement annotation, but there it means the pre-state of the
  **caller**, not the state before the call. The instance checks another location without any
  message (`-check` passes), and WP proves a false property.
- **`Here`** in the callee's `assumes` clauses (where `\valid(p)`, a labelled logic function such
  as `len(p)`, and `\at(*p, Here)` are typed with `Here`) or in `assigns` (`\at(*p, Here)`)
  denotes the callee's pre-state. When a property uses `After`, the assertion is placed after the
  call, where `Here` evaluates in the **post-state** instead of before the call, and WP proves a
  false property.

The same visitor builds the `\read` instances of a `\reading` property from the `\from` parts,
and the hypotheses taken from the assumes clauses of each behavior; both keep the labels too
(checked: `len{Old}`, `\old` and `\at(.,Pre)` in the caller's assertions).

The component at fault is MetAcsl. E-ACSL and WP are right to refuse `Old` in an assertion; the
kernel refuses the same annotation written by hand.

## Where the pipeline meets it

The E-ACSL build loads the module's meta file (`EACSL_META_FLAGS` in
[`../../../scripts/eacsl_toolchain.py`](../../../scripts/eacsl_toolchain.py): `-meta -meta-warn-key
unknown-func=inactive`, then `-then-last` and the E-ACSL options), and
[`../../../templates/metacsl/eacsl_libc_writers.h`](../../../templates/metacsl/eacsl_libc_writers.h)
gives the libc writers an assigns clause so that a `\writing` property is checked at their calls.
With `assigns __dest[0 .. strlen(__src)] \from __src[0 .. strlen(__src)];` on `strcpy`, E-ACSL
aborted. `strcpy`, `strcat`, `stpcpy` and the other writers whose bound is a logic function of
their arguments stay in `EACSL_META_LIBC_UNCHECKED`. See the symptom "E-ACSL Aborts With `invalid
label 'Old'`..." in
[`../../troubleshooting/eacsl-and-fuzzing.md`](../../troubleshooting/eacsl-and-fuzzing.md). That
entry first blamed E-ACSL and has been corrected to attribute the cause to MetAcsl.

## Evidence

Run on 2026-11-20 in `framac-analysis:latest` (Frama-C 34.0~beta, MetAcsl 0.12~beta), with
[`./repro/47-metacsl-callee-old-label-in-written.sh`](./repro/47-metacsl-callee-old-label-in-written.sh).
Three variants of the callee's assigns clause: `len(p)` with `len{L}` a user logic function
(implicit `Old`), `\old(*p)`, and `\at(*p, Pre)`:

```
34.0~beta (Selenium)
len: bound len{Old}(&n)
len: reparse: logic label `Old' not found. Ignoring code annotation
len: wp: [kernel] Unexpected error (Wp__NormAtLabels.LabelError(_)).
len: e-acsl: [kernel] Plug-in e-acsl aborted: internal error (invalid label 'Old' within statement annotation 'Assertion' in '&n').
old: bound \old(*(&n))
old: reparse: \old undefined in this context. Ignoring code annotation
old: wp: [kernel] Unexpected error (Wp__NormAtLabels.LabelError(_)).
old: e-acsl: [kernel] Plug-in e-acsl aborted: internal error (invalid label 'Old' within statement annotation 'Assertion' in '\old(*(&n))').
pre: bound \at(*(&n),Pre)
pre: reparse: ok
pre: wp: stays_in_prefix proved
pre: e-acsl: translated
RESULT: the instance keeps the labels of the callee (3 of 3 cases)
```

`stays_in_prefix` (`\subset(\written, out + (0 .. 3))`) is false: `caller` has `requires n == 2`,
sets `n` to 7 through a defined function, then calls `fill(out, &n)`, which writes `out[0 .. 7]`.
With `Pre`, the instance reads `n` at the entry of `caller` (2), and WP proves it.

Other checks:

- **The kernel refuses `Old` in an assertion.** Written by hand, `/*@ assert \separated(&buf[0] +
  (0 .. \old(strlen("abc"))), &secret); */` gives `\old undefined in this context` and
  `strlen{Old}("abc")` gives ``logic label `Old' not found``, both as `annot-error`. ACSL 1.24
  (implementation manual, table 2.1 and the list below it) allows `Old` in assigns and ensures
  clauses of contracts only, and gives `Pre` in a statement annotation the pre-state of the
  enclosing function.
- **The libc case.** With a user function `void copy(char *d, const char *s)` specified with
  `assigns d[0 .. strlen(s)] \from s[0 .. strlen(s)];` (libc `<string.h>` for `strlen`), the kernel
  prints the clause as `assigns *(d + (0 .. strlen{Old}(s))) \from *(s + (0 .. strlen{Old}(s)));`,
  the instance at `copy(buf,"abc")` is `\separated(&(buf[0]) + (0 .. strlen{Old}(&("abc"[0]))),
  &secret)`, and E-ACSL aborts with `invalid label 'Old' within statement annotation 'Assertion'
  in '&("abc"[0])'`. This is the pipeline's `strcpy` case without the libc declaration of `strcpy`.
- **All four instantiation modes.** The same happens with `-meta-fold` (the label ends up in the
  argument of the folded predicate), with `-meta-quantify-range` (in the quantifier bound), and
  with a property that uses `After` (the assertion follows the call; `Old` stays).
- **`Here` in `assumes` and `assigns`.** In a function contract's `assumes` clause, Frama-C types
  `\valid(p)`, `len(p)` and `\at(*p, Here)` with `BuiltinLabel Here` (the callee's pre-state). In
  `assigns`, WP also evaluates `\at(x, Here)` in the callee's pre-state (checked: `requires x == 2;
  assigns x, a[\at(x, Here)]; ensures x == 5;` is proved when the body writes `a[2]` and fails when
  it writes `a[5]`, whereas `\at(x, Post)` proves `a[5]`). Under an `After` property
  `\separated(\written, &secret) || \at(secret, After) == \at(secret, Before)` on a callee with
  `behavior active: assumes len(p) > 0; assigns *p, *d; ensures *p == 0;` called as
  `mutate(&n, &secret)` under `requires n == 1;`, keeping `Here` generates
  `len(&n) > 0 ==> \at(secret, Here) == \at(secret, meta_pre_0)` after the call: `len(&n)` reads
  the post-state (`n == 0`), so the hypothesis is false and WP proves 3 of 3 goals for a false
  property.
- **MetAcsl `master`** (`4f43801390`, built against the installed 34.0~beta kernel, see
  [Validation](#validation)) gives the same "before" output as the installed 0.12~beta.

## Cause

`inspect_contract` in `meta_annotate.ml` (lines 553 to 596 on `master`) builds a visitor whose
only method, `vterm`, replaces an lvalue rooted at a formal by the actual argument; labels are not
visited. It applies it to the assumes clauses of each behavior and hands it, with the assigns
list, to `external_assigns` (writing context) or `passthrough_from` (reading context, the `\from`
parts). These pass each visited location to `writing_instance` / the reading instance, which put
it in place of `\written` / `\read`, with the assumes as hypotheses, and `instantiate` attaches
the assertion to the call statement (before it, or on a new statement after it when the property
uses `After`).

The term or assumes predicate is typed for the callee's contract: `Old`, `Pre` and `Here` in
`assumes`, `assigns` and `\from` clauses all denote the pre-state of the callee, which is the state
just before the call. (Inside `\at(..., Init)`, an unlabelled `len(p)` is typed with `BuiltinLabel
Init`, not `Here`, so `Init` stays untouched.) In the caller's statement annotation, that pre-state
is `Here` when the assertion precedes the call, and a label on the call statement when it follows
it.

## Fix

MetAcsl already has a label for "the state before the instrumented statement": the meta label
`Before` (`FormalLabel "Before"`). `replace_after_before`, applied to every instance, turns it into
`Here` when the assertion precedes the statement and into `StmtLabel` of the statement when it
follows it, and `instantiate` adds a C label (`meta_pre_N`) to the statement in that case
(`before_present`). The patch adds to the substitution visitor of `inspect_contract`:

```ocaml
method! vlogic_label = function
  | BuiltinLabel (Old | Pre | Here) -> Cil.ChangeTo (FormalLabel "Before")
  | _ -> Cil.DoChildren
```

11 lines in `meta_annotate.ml` with the comment, a CHANGELOG line, and a new test
`tests/meta/callee_labels.c` with its four oracles in `oracle/` and `oracle_fold/` (run with and
without `-meta-quantify-range`):

- `\writing` before call (`len`, `\old`, `Pre`, `Here`) and `After` (`len`, `Here`), folded
  cleanly in `oracle_fold/`;
- `\reading` without `assumes` (`len`, `\old`, `Pre` in `\from`, with `char *s` so `fold.0`
  re-parses without hitting a pre-existing `set<char const *>` parser quirk), folded cleanly in
  `oracle_fold/`;
- `assumes` clauses (`\valid`, `len`, `Here`, `Pre`) under an `After` property whose predicate
  does not mention `Before` (exercising `meta_pre_N` insertion) and in a two-behavior `\reading`
  callee (`copy`), both marked `\flags(fold:no)` because `-meta-fold` shares folded predicates by
  type signature across behaviors (so `oracle_fold/` does not bake in broken folding semantics).

`tests/**` has `header_spec=.ignore` in `.gitattributes`, so the new files need no header; the
oracles end with an empty line like the existing ones (`git am` notes trailing whitespace and a
new blank line at EOF, as Frama-C prints them). The visitor is `frama_c_inplace`, but terms and
predicates are rebuilt when a child changes, so the callee's contract is not modified (checked: it
prints as before, `assigns *(d + (0 .. len{Old}(p)));`).

### Validation

Built in a throwaway `framac-analysis:latest` container: `dune build @install` of `master`
(`4f43801390`) with and without the patch, both with the one `PLpointer_comparable` case of
`meta_parse.ml` removed (a constructor of the kernel after 34.0~beta; `master` does not build
against 34.0~beta without that). The resulting `MetAcsl.cmxs` replaced the installed one.

- **Reproducer before and after the patch:** stock 0.12~beta and unpatched `master` both exit 1
  (`RESULT: the instance keeps the labels of the callee (3 of 3 cases)`). After the patch (exit 0):

  ```
  34.0~beta (Selenium)
  len: bound len(&n)
  len: reparse: ok
  len: wp: stays_in_prefix not proved
  len: e-acsl: translated
  old: bound \at(*(&n),Here)
  old: reparse: ok
  old: wp: stays_in_prefix not proved
  old: e-acsl: translated
  pre: bound \at(*(&n),Here)
  pre: reparse: ok
  pre: wp: stays_in_prefix not proved
  pre: e-acsl: translated
  RESULT: the instance is in the state before the call
  ```

- **`After` placement and `Here` in `assumes`:**
  - On the `mutate` soundness check (`assumes len(p) > 0; assigns *p, *d; ensures *p == 0;` under
    an `After` property): without mapping `Here`, WP proves 3 of 3 goals; with `Old | Pre | Here`,
    the assertion becomes `len{meta_pre_0}(&n) > 0 ==> \at(secret, Here) == \at(secret, meta_pre_0)`
    and WP does not prove it (2 of 3 goals, timeout on the false assertion).
  - On `assumes \valid(p); assumes len(p) > 0; assumes \at(*p, Here) > 0; assumes \at(*p, Pre) > 0;
    assumes \at(len(p), Init) > 0;` with `assigns d[0 .. \at(*p, Here)], d[0 .. len(p)];`:
    before-call assertions stay in `Here`, `After` assertions (both with and without `Before` in
    the meta property) get `meta_pre_N` on all four pre-state clauses while `Init` stays `Init`;
    `-check`, re-parse, WP (12 of 12 goals) and E-ACSL translation all succeed in default and
    `-meta-fold` modes.
- **`\read` and assumes (`t5.c` from the issue):** before, `len{Old}`, `\old` and `\at(*(&n),Pre)`
  in the caller, the re-parse fails and WP stops with `LabelError`; after, `\at(*(&n),Here)` and
  `len(&n)`, `-check` and re-parse succeed and WP proves 6 of 6 goals.
- **MetAcsl suites `tests/meta` and `tests/meta-wp` (default and fold configurations):** `dune
  build @tests/meta/ptests` cannot run in the image (the `(package frama-c)` dependency asks for
  documentation files the image does not ship), so every test command that `frama-c-ptests`
  generated for `tests/meta` and `tests/meta-wp` in both configurations was run by hand and its
  logs compared with the oracles and with unpatched `master` (built the same way):
  - With the patch: `tests/meta` 23 of 23 match oracles in default and 23 of 23 in fold (empty
    stderr); `tests/meta-wp` 12 of 12 match oracles in default and 12 of 12 in fold (empty stderr).
  - Without the patch (with the new test copied in): all 21 + 21 existing `tests/meta` runs and
    12 + 12 `tests/meta-wp` runs are byte-for-byte identical to the patched build (0 diffs), while
    all 4 runs of `callee_labels.c` fail in `-check` (`Logic label Old is not declared in this
    scope`, exit code 4).
  - All 4 printed outputs of `callee_labels.c` (`default.0`, `default.1`, `fold.0`, `fold.1`) also
    re-parse cleanly with `frama-c -check`.
- **Patch application:** `git apply --check` and `git am --keep-non-patch` both succeed on
  pristine `4f43801390`.
- **Not run:** `tests/meta-deduce` (SWI-Prolog absent), MetAcsl's CI, lint/header checks, and a
  build against the kernel `master` targets.

## Not covered

- **`Post`.** ACSL allows `Post` in an assigns clause. A location that depends on the post-state
  of the callee cannot be evaluated before the call; the patch leaves it as it is (as for
  `\result`, which `external_assigns` already skips). Not tried.
- **Unlabelled memory reads with `After`.** In an assigns clause (`d[0 .. *p]`) or an assumes
  clause (`*p <= 2`), an unlabelled `*p` (`TLval (TMem _, _)`) has no `logic_label` node, so
  `vlogic_label` does not rewrite it. When the property uses `After`, the assertion follows the
  call, where an unlabelled `*p` is read after it. The patch does not change this.
- **pub/meta#4** (`__invalid_label` for `Before` in a `switch` case) is about the statement label
  `Before` becomes when the assertion follows the call. A callee with `Old`, `Pre` or `Here` in
  its contract, under an `After` property and in such a `switch` case, would meet it too. Not
  tried.
- **Other pre-existing defects seen on the way, not part of this report:**
  - `-meta-fold` keys folded predicates by `(name, type_sig)` only, ignoring `assumes` clauses, so
    two behaviors whose `\from` or `assigns` terms share a type silently reuse the first
    behavior's folded predicate and drop the second behavior's `assumes`. That is why
    `callee_labels.c` marks its behavior-guarded properties `\flags(fold:no)`.
  - `-meta-fold`'s `create_formals` strips qualifiers on top-level `Ctype` only, leaving `const`
    inside `set<char const *>`, which the ACSL parser rejects on re-parse (`unexpected token
    'const'`).
  - E-ACSL aborts with `typing was not performed on construct len(&n)` on a hand-written
    `/*@ assert \forall integer i; 0 <= i <= len(&n) ==> \separated(&buf[0] + i, &secret); */`
    with `logic integer len{L}(int *n) = \at(*n, L);` (no MetAcsl involved; 34.0~beta).
    `-meta-quantify-range` produces this form after the patch for the `len` variant.
  - WP marks the folded instance `meta_no_write_secret(&(buf[0]) + (0 .. len(&n)))` as
    `Degenerated` (`Non-expected set of values`) under `-meta-fold`; the goal is not proved.

## Duplicates

Searched on 2026-11-20 through the read-only API (`glab api`):

- `pub/meta` (869), issues in all states, terms `Old`, `label`, `written`, `assigns`, `writing`,
  `LabelError`, `E-ACSL`: #4 (open, `__invalid_label` in calling contexts with `switch` cases,
  related but different, see above) and #3 (closed, `\written` and `\read` on a bit-field). The
  tracker has three issues in all (#1, #3, #4).
- `pub/frama-c` (780), terms `invalid label`, `label Old`, `MetAcsl`, `meta`, `LabelError`,
  `within statement annotation`: nothing about MetAcsl instances. #1350 (closed, "Unexpected
  label Old in pre") and #2800 (open, `<==>` over a labelled term in E-ACSL) are about other
  constructs.

## Filing

- Target: `pub/meta`. [`../../../tools/upstream_audit/file_upstream.py`](../../../tools/upstream_audit/file_upstream.py)
  files on `pub/frama-c` (project 780) only, so this one is filed by hand or after the tool
  learns a project option.
- Not filed: no branch was pushed, and no issue or merge request was created. The MR text holds
  `#<issue>`. The patch applies with `git am --keep-non-patch` on `4f43801390` (checked).

## For the pipeline

Until a MetAcsl release carries the fix, `strcpy`, `strcat` and the other writers whose bound is a
logic function of their arguments stay unchecked (`EACSL_META_LIBC_UNCHECKED`). The fix alone does
not make them checked in the E-ACSL build: with the patched MetAcsl, the `copy` example above no
longer aborts, the instance reads `strlen(&("abc"[0]))` before the call, and E-ACSL ignores it
with ``E-ACSL construct `logic functions or predicates performing read accesses' is not yet
supported. Ignoring annotation.`` (the instrumented `main` has no check for it). The libc
`strlen` is an axiomatic logic function that reads memory. Checking these writers would also need
a bound that E-ACSL can evaluate; not explored.
