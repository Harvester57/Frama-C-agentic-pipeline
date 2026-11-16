# [wp] probes must not drop the variables of the goal

- Source branch: `fix/wp-probe-keeps-vars` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `3dff90fc70`. Patch: [`../patches/19-wp-counter-examples-drops-frame.patch`](../patches/19-wp-counter-examples-drops-frame.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #2811.

## Problem

`CfgWP.probe_vc` replaces the free variables of the VC (`vc.vars`) with the variables of the probed
term. `passify_vc` relies on them (through `occurs_vc`) to keep the passive equalities of labels and
merges, so after a probe an equality such as `Mptr_0 = Mptr_1`, between the pre-state and
post-state memories of a chunk the function never writes, is dropped when `Mptr_1` occurs only in
the goal. A valid postcondition such as `ensures p->ptr == \old(p->ptr);` on a function that writes
only integer fields of `*p` then becomes `Prove: Mptr_0[a] = Mptr_1[a].` with no hypothesis on the
two memories: Alt-Ergo times out, Z3 and CVC5 answer `Unknown` with a spurious model. It happens
with `-wp-counter-examples` (which probes the formals) and with any `probe` annotation, without the
option.

## Change

`plugins/wp/src/cfgWP.ml`, `probe_vc`: `vars = V.union (F.vars term) vc.vars`, so a probe adds its
variables to the VC instead of replacing them, as `assume_vc` keeps them.

New test `plugins/wp/tests/wp_ce/probes_frame.i`, default configuration (`-wp-prover none
-wp-print`), run with `-wp-counter-examples` and without; the second function has a `probe`
annotation. Both oracles show `Prove: true.` for `keep_ptr`; before the fix, the first function
gives `Prove: Mptr_0[a] = Mptr_1[a].` with the option and the second one in both runs.
`DONTRUN` for the `qualif` and `ce` configurations, like `probes.i`.

## Testing

On a build of `3dff90fc70` with the patch (Debian 13, OCaml 5.5 switch, Alt-Ergo 2.4.3, Z3, CVC5):

- Reproducer from the issue: before, `keep_ptr` is `Prove: Mptr_0[a] = Mptr_1[a].` and Alt-Ergo
  times out, with `-wp-counter-examples` and with the probe annotation; after, `Prove: true.` and
  `Proved goals: 1 / 1` (Qed) in both cases; with `-wp-no-let`,
  `Have: (Mptr_0 = Mptr_1) /\ (p_1 = p).` is back.
- Goals that genuinely fail still get models: `ensures p->len == 1;` and
  `ensures p->ptr != \old(p->ptr);` are `[Unknown] ... (CVC5) (Model)` with
  `-wp-counter-examples`, before and after.
- ptests, default configuration: `dune build @plugins/wp/tests/ptests_config` (426 results) passes;
  the only changes are the two new oracles of `wp_ce/probes_frame.i` (no existing oracle changed,
  including `wp_ce/probes.i`).
- Not run: the `qualif` and `ce` configurations (no WP cache in my environment; `cvc4_ce.i` needs
  CVC4).
- `dune build --profile dev @plugins/wp/check`: exit 0, no output.
- `git diff --check`: clean.
- `./dev/check-files.sh -p` (that is, `make check-lint` and `make check-headers` on the changed
  files) with ocp-indent 1.10.0 and clang-format 19.1.7: clean.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
