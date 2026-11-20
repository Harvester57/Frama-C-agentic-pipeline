# [meta] do not copy callee Old/Pre/Here labels into \written and \read instances

- Source branch: `fix/meta-callee-labels-in-written` on the fork of `pub/meta`; target branch `master`.
- Based on: `4f43801390`. Patch: [`../patches/47-metacsl-callee-old-label-in-written.patch`](../patches/47-metacsl-callee-old-label-in-written.patch)
- `pub/meta` has no merge request template (no `.gitlab/` directory at `4f43801390`), so the
  description has no contribution checkboxes.

<!-- Everything below this line is the merge request description. Tracker: pub/meta (MetAcsl), not pub/frama-c. -->

Closes #<issue>.

## Problem

At a call to a function known by its contract, `inspect_contract` replaces the formals of each
assigns location (or `\from` location) and of the assumes clauses by the actual arguments, and
the location becomes `\written` (or `\read`) in an assertion of the caller, under the assumes as
hypotheses. The labels of the contract are copied unchanged:

- `Old` (an explicit `\old`, or the label the kernel gives to a labelled logic function called
  without one in an assigns clause, such as `strlen(s)`) is not allowed in a statement annotation:
  `-check` reports `Logic label Old is not declared in this scope`, the printed code does not
  re-parse, WP stops with `Wp__NormAtLabels.LabelError`, E-ACSL with `invalid label 'Old' within
  statement annotation 'Assertion'`;
- `Pre` is allowed but denotes the pre-state of the caller, so the instance checks another
  location, and WP can prove a false property;
- `Here` (in an `assumes` clause — where `\valid(p)`, a labelled logic function such as `len(p)`,
  and `\at(*p, Here)` are typed with `Here` — or in an `assigns` clause as `\at(*p, Here)`)
  denotes the callee's pre-state, but under a property that uses `After` the assertion follows the
  call, so `Here` evaluates in the post-state instead and WP can prove a false property.

## Change

`meta_annotate.ml`, 11 lines added: the substitution visitor of `inspect_contract` maps
`BuiltinLabel (Old | Pre | Here)` to the meta label `Before`. In a callee's `assumes`, `assigns`
and `\from` clauses, all three denote the pre-state of the callee, the state just before the call.
`replace_after_before` already turns `Before` into `Here` when the assertion precedes the call,
and into a statement label on the call (added by `instantiate`) when a property that uses `After`
puts the assertion after it. The same visitor serves the writing and the reading contexts and the
assumes clauses, so all three are covered. `Init` and `Post` are left unchanged.

The visitor rebuilds the terms and predicates it changes, so the callee's contract is unchanged.

New test `tests/meta/callee_labels.c`:

- assigns clauses with an implicit `Old` (a labelled logic function), `\old`, `\at(., Pre)` and
  `\at(., Here)` under a before-call `\writing` property and an `After` property (folded cleanly
  in `oracle_fold/`);
- `\from` parts with implicit `Old`, `\old` and `\at(., Pre)` under a `\reading` property (folded
  cleanly in `oracle_fold/`);
- `assumes` clauses (`\valid`, labelled logic function, `Here`, `Pre`) under an `After` property
  whose predicate does not mention `Before` (exercising `meta_pre_N` insertion) and in a
  two-behavior `\reading` callee, both marked `\flags(fold:no)` because `-meta-fold` shares folded
  predicates by type signature across behaviors;
- run with and without `-meta-quantify-range`, four oracles (`oracle/` and `oracle_fold/`, `.0`
  and `.1`). A `CHANGELOG.md` line under "Version dev".

## Testing

On `4f43801390` built against Frama-C 34.0~beta (Debian 13, OCaml 5.5 switch). `master` does not
build against 34.0~beta as it is, so both builds below remove the one `PLpointer_comparable` case
of `meta_parse.ml`; nothing else differs.

- **Reproducer from the issue:**
  - default (`len{Old}`): before, the re-parse fails and WP and E-ACSL stop; after, the instance
    is `\subset(&(out[0]) + (0 .. len(&n)), &out[0 .. 3])`, the printed code re-parses, E-ACSL
    completes its translation, and WP does not prove `stays_in_prefix` (10 of 11 goals);
  - `-DUSE_OLD`: same, with `\at(*(&n),Here)`;
  - `-DUSE_PRE`: before, `\at(*(&n),Pre)` and WP proves all 11 goals; after,
    `\at(*(&n),Here)` and `stays_in_prefix` is not proved.
- **`After` property and `Here` in `assumes`:**
  - `behavior active: assumes len(p) > 0; assigns *p, *d; ensures *p == 0;` called on `(&n, &secret)`
    with `requires n == 1;` under `\separated(\written, &secret) || \at(secret, After) == \at(secret, Before)`:
    when `Here` is kept, the post-call assertion reads `len(&n) > 0` in the post-state (`n == 0`)
    and WP proves all 3 goals; with the patch, it reads `len{meta_pre_0}(&n) > 0` and WP does not
    prove the false property (2 of 3 goals).
  - `assumes \valid(p); assumes len(p) > 0; assumes \at(*p, Here) > 0; assumes \at(*p, Pre) > 0;
    assumes \at(len(p), Init) > 0;` under before-call and `After` properties (including one without
    `Before` in its predicate): before-call assertions stay in `Here`, `After` assertions get
    `meta_pre_N` on all four pre-state clauses while `Init` stays `Init`; `-check`, re-parse, WP
    (12 of 12 goals) and E-ACSL translation all succeed in both default and `-meta-fold` modes.
- **`\read` example from the issue:** before, the re-parse fails and WP stops with
  `LabelError`; after, the assertions hold `\at(*(&n),Here)` and `len(&n)`, `-check` and the
  re-parse succeed, and WP proves 6 of 6 goals.
- **Suites `tests/meta` and `tests/meta-wp`, default and fold configurations:** `dune build
  @tests/meta/ptests` could not run in my environment (a `(package frama-c)` dependency on
  documentation files that the installation does not ship), so I ran every command `frama-c-ptests`
  generated for `tests/meta` and `tests/meta-wp` in both configurations and compared the logs with
  the oracles and with unpatched `master` (built the same way):
  - with the patch: `tests/meta` 23 of 23 equal in default and 23 of 23 in fold (empty stderr);
    `tests/meta-wp` 12 of 12 equal in default and 12 of 12 in fold (empty stderr);
  - without the patch (with the new test copied in): all 21 + 21 existing `tests/meta` runs and
    12 + 12 `tests/meta-wp` runs are byte-for-byte identical to the patched build (0 diffs), while
    all 4 runs of `callee_labels.c` fail in `-check` (`Logic label Old is not declared in this
    scope`, exit code 4);
  - all 4 printed outputs of `callee_labels.c` (`default.0`, `default.1`, `fold.0`, `fold.1`) also
    re-parse cleanly with `frama-c -check`.
- **Headers:** `tests/**` is `header_spec=.ignore`, so the new files carry no header. Like the
  existing oracles, the new ones end with an empty line.
- **Not run:** `tests/meta-deduce` (SWI-Prolog not installed), lint/header checks, and a build
  against the kernel's `master`.

The change does not handle `Post` in an assigns clause (a location that depends on the callee's
post-state cannot be checked before the call), nor an unlabelled memory read such as `*p` (in
`assigns` or `assumes`) when the assertion is placed after the call.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
