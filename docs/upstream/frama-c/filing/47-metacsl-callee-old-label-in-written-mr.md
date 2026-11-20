# [meta] do not copy callee Old/Pre labels into \written and \read instances

- Source branch: `fix/meta-callee-labels-in-written` on the fork of `pub/meta`; target branch `master`.
- Based on: `4f43801390`. Patch: [`../patches/47-metacsl-callee-old-label-in-written.patch`](../patches/47-metacsl-callee-old-label-in-written.patch)

<!-- Everything below this line is the merge request description. Tracker: pub/meta (MetAcsl), not pub/frama-c. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

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
  location, and WP can prove a false property.

## Change

`meta_annotate.ml`, 10 lines added: the substitution visitor of `inspect_contract` maps
`BuiltinLabel Old` and `BuiltinLabel Pre` to the meta label `Before`. Both denote the pre-state of
the callee, the state just before the call. `replace_after_before` already turns `Before` into
`Here` when the assertion precedes the call, and into a statement label on the call (added by
`instantiate`) when a property that uses `After` puts the assertion after it. The same visitor
serves the writing and the reading contexts and the assumes clauses, so all three are covered.

The visitor rebuilds the terms it changes, so the callee's contract is unchanged.

New test `tests/meta/callee_labels.c`: assigns clauses with an implicit `Old` (a labelled logic
function), `\old` and `\at(., Pre)`, under a `\writing` property placed before the call and one
that uses `After`, and a callee with two behaviors (`Pre` in an assumes, `Old` in the `\from`
parts) under a `\reading` property; run with and without `-meta-quantify-range`, oracles for the
default and the fold configurations. A CHANGELOG line under "Version dev".

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
- **`After` property:** the call gets `meta_pre_0:` and the instance reads `len{meta_pre_0}(&n)`,
  in the default, `-meta-fold` and `-meta-quantify-range` modes; the printed code re-parses.
- **`\read` example from the issue:** before, the re-parse fails and WP stops with
  `LabelError`; after, the assertions hold `\at(*(&n),Here)` and `len(&n)`, the printed code
  re-parses and WP proves 6 of 6 goals.
- **Suite `tests/meta`, default and fold configurations:** `dune build @tests/meta/ptests` could
  not run in my environment (a `(package frama-c)` dependency on documentation files that the
  installation does not have), so I ran every command `frama-c-ptests` generated for `tests/meta`
  and compared the logs with the oracles. With the patch, 23 of 23 equal in each configuration.
  Without it, the 21 existing tests are equal and the new test stops in `-check` (`Logic label
  Old is not declared in this scope`).
- **Headers:** `tests/**` is `header_spec=.ignore`, so the new files carry no header. Like the
  existing oracles, the new ones end with an empty line.
- **Not run:** the suites `meta-wp` and `meta-deduce`, and a build against the kernel's `master`.

The change does not handle `Post` in an assigns clause (a location that depends on the callee's
post-state cannot be checked before the call), nor an unlabelled read such as `*p` in the
location when the assertion is placed after the call.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
