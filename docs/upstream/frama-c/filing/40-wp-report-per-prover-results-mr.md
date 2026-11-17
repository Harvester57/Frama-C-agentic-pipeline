# [wp] manual: unit of "time" and meaning of "cached" in the JSON report

- Source branch: `doc/wp-manual-json-report-fields` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `95408044f7`. Patch: [`../patches/40-wp-report-per-prover-results.patch`](../patches/40-wp-report-per-prover-results.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Related to #2829. This only corrects the manual; the feature request of that issue (per-prover
results in the JSON report) stays open.

## Problem

Two sentences of the WP manual about the `-wp-report-json` output do not match the report
(`plugins/wp/doc/manual/wp_plugin.tex`, the list of fields of a goal):

- `"time"` of a prover is described as "prover time, in milliseconds". The value is `Stats.time`, a
  sum of `VCS.prover_time` values (`solver_time` for Qed), in seconds. On a goal that Alt-Ergo proves,
  `-wp-msg-key prover` prints `Valid (15ms)` and the report has `"time": 0.0154`.
- `"cached"` is described as "number of cached sub-goals verdicts (including Qed proved sub-goals)".
  It is the number of prover results read from the cache (`Stats.add_cached`): one per prover and
  sub-goal, and never for Qed (`Stats.cacheable` requires `p <> Prover.Qed`). A goal tried with three
  provers has `"cached": 3` on a second run with `-wp-cache update`.

## Change

- `plugins/wp/doc/manual/wp_plugin.tex`: "in milliseconds" becomes "in seconds", and the description
  of `"cached"` becomes "number of prover results read from the cache, one per prover and sub-goal;
  Qed results are not counted".

No code changes.

## Testing

- The two values quoted above were read on `master` at `95408044f7` (Alt-Ergo 2.6.4, Z3 4.13.3,
  CVC5 1.1.2) with the file of #2829.
- `./dev/check-files.sh -p HEAD~1`: passes.
- The manual was not built (no LaTeX in the image used for the build). The change keeps the
  existing macros (`\texttt{Qed}`) and adds none.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
checks described above.
