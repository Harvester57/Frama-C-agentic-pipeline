# WP: with several provers, `-wp-report-json` keeps one prover per goal; the manual misdescribes `"time"` and `"cached"`

Draft feature request for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues),
with two documentation bugs in the same text. Filed on 2026-11-18 as [#2829](https://git.frama-c.com/pub/frama-c/-/work_items/2829), with merge request [!57](https://git.frama-c.com/pub/frama-c/-/merge_requests/57). Issue 40 of this folder.
The feature request has no patch; the merge request corrects the two manual sentences only and
does not close the issue.

**Filing package:** [issue](./filing/40-wp-report-per-prover-results-issue.md), [merge request](./filing/40-wp-report-per-prover-results-mr.md), [reproducer](./repro/40-wp-report-per-prover-results.sh), [manual patch](./patches/40-wp-report-per-prover-results.patch)

## Summary

With `-wp-prover alt-ergo,z3,cvc5`, WP keeps one result per goal, the "best" prover's. That result
is what goes to the console line and to the JSON report. On a goal that no
prover proves, the other provers' answers are lost from every machine-readable output:

- Timeout against Unknown;
- the time a prover took before giving up;
- the steps.

`-wp-status` shows them, but only as human-readable text.

The pipeline wants them per goal. The cost hint of `scripts/run_wp_function.py` has to tell a quick
Unknown, which means the goal is false or out of reach, from a Timeout, which means a longer timeout
or another prover may succeed. With three provers, a merged Timeout hides CVC5's quick Unknown.

## The four observations, sorted

The observations come from the pipeline's troubleshooting entry
([`../../troubleshooting/wp-and-guardrail.md`](../../troubleshooting/wp-and-guardrail.md), "A False
Goal Reads `[wp] [Timeout] ...` With Three Provers"). Each was checked on master `95408044f7`
against the code.

| # | Observation | Verdict | Code (master `95408044f7`) |
|---|---|---|---|
| 1 | The console shows one `[Timeout] ... (Alt-Ergo)` line, though CVC5 alone answers `[Unknown]` | **by design**; part of the feature request | `VCS.compare` (`VCS.ml:281`) ranks a valid result first, then a larger model, then the higher `vrank` (`VCS.ml:259`: Unknown 3 < Timeout 4); `VCS.best` folds the provers with it, and `Stats.results` (`Stats.ml:108-127`) keeps `Qed` plus that one prover |
| 2a | The JSON `"provers"` array lists `qed` and one prover | **feature request** | `register.ml:290-344`: `do_report_json` writes `ProofEngine.consolidated g`, built from `Stats.results`. Every prover's result is still in `Wpo.get_results g` |
| 2b | The prover's `"time"` is `0` on every unproved goal (Qed's is not) | **by design** (only proof times are summed) | `Stats.presult` (`Stats.ml:80`) returns `pzero` unless the result is valid |
| 2c | `"time"` of a proved goal is in seconds (`0.0111` for about 11 ms), but the manual says milliseconds | **documentation bug** | `wp_plugin.tex:2302` "prover time, in milliseconds"; `pstats_to_json` writes `r.Stats.time`, which is `prover_time` in seconds. A `-wp-msg-key prover` run printed `Valid (12ms)` and the JSON `0.0123` |
| 3a | Under `-wp-cache update`, the console says `(Cached)` on the run that fills the cache | **by design** since 2022 (`(Cached)` with `updating` means "now in the cache") | `Stats.pp_stats` (`Stats.ml:231`) prints ` (Cached)` when `updating \|\| cachemiss = 0`; commits `31e5cc5842`, `c3243f75cc`, `dbcf5c19f0` |
| 3b | The JSON `"cached"` appears only on a real cache hit, and is 3 on one goal | the count is correct, but the **manual's definition is wrong** | `Stats.add_cached` (`Stats.ml:106`) counts prover results read from the cache, one per prover, excluding `Qed` (`cacheable`: `p <> Prover.Qed`). `wp_plugin.tex:2315-2316` says "number of cached sub-goals verdicts (including Qed proved sub-goals)" |
| 4a | Only `-wp-msg-key prover` prints every prover's answer, without the goal name, interleaved under `-wp-par` | **partly inaccurate**: `-wp-status` prints each prover's answer under each goal (below), but as text only; the `prover` debug lines are for debugging | `ProverWhy3.ml:138-142` |
| 4b | That debug line has no time for an Unknown answer | **by design, not to change**: an Unknown result is built without `pr_time` and `pr_steps` | `ProverWhy3.ml:132-134` (`VCS.result ~model ... VCS.Unknown`, since `7930433ed6`); the result's time feeds `VCS.configure` and the cache, so changing it is not a reporting fix |

`-wp-status` on master, `fast_unknown`:

```
Goal Post-condition 'fast_false' in 'fast_unknown':
[...]
Prove: 51 <= fast_unknown_0.
Prover Alt-Ergo 2.6.4 returns Timeout (Qed:0.58ms) (4s)
Prover CVC5 1.1.2 returns Unknown (Qed:0.58ms)
Prover Z3 4.13.3 returns Timeout (Qed:0.58ms) (4s)
```

So per-prover answers are already available per goal as text. The feature request is to put them in
`-wp-report-json`.

## What to ask for

Issue only. The change touches the JSON schema, which tools may parse, and there is a choice to
make, so it is not "small and uncontroversial". Options for the maintainers:

1. Add a per-prover array, for example `"results": [{"prover", "verdict", "time", "steps",
   "cached"}]`, from `Wpo.get_results g`. Keep `"provers"` as it is. This is backward compatible.
2. Behind an option (`-wp-report-json-all`, or a JSON verbosity level), the same array.
3. Document that only the best prover is reported, and point to `-wp-status`.

Fix the two manual sentences in any case: `"time"` is in seconds, and `"cached"` counts prover
results read from the cache, excluding Qed. A manual-only MR would be small. It is not prepared
here, because the brief asks for issue only on the feature, and the wording is better left to the
maintainers with the issue.

There is no `-wp-report-json` test in `plugins/wp/tests`. Option 1 or 2 would need a new test.

## Versions

| | Result |
|---|---|
| `35.0~~dev (Bromine)`, `master` at `95408044f7` (image `framac-master-audit:9540804`; Alt-Ergo 2.6.4, Z3 4.13.3, CVC5 1.1.2) | all four observations reproduce, `RESULT: present` |
| `34.0~beta (Selenium)` (image `framac-analysis:latest`; Alt-Ergo 2.4.3, same Z3 and CVC5) | identical prover answers and JSON shape, `RESULT: present` |

## Reproduction

[`./repro/40-wp-report-per-prover-results.sh`](./repro/40-wp-report-per-prover-results.sh) runs WP
on [`./repro/40-wp-report-per-prover-results.c`](./repro/40-wp-report-per-prover-results.c) in
four steps:

1. each prover alone;
2. the three provers together, printing the console lines, the `-wp-status` answers and the
   flattened `-wp-report-json`;
3. two runs with `-wp-cache update`, printing `"cached"`;
4. a check that decides `RESULT`: the JSON lists one non-Qed prover per goal while `-wp-status` saw
   three.

On master:

```
--- alt-ergo alone
[wp] [Timeout] typed_fast_unknown_ensures_fast_false (Alt-Ergo)
[wp] [Timeout] typed_hard_true_assert_fermat3 (Alt-Ergo)
--- z3 alone
[wp] [Timeout] typed_fast_unknown_ensures_fast_false (Z3)
[wp] [Unknown] typed_hard_true_assert_fermat3 (Z3)
--- cvc5 alone
[wp] [Unknown] typed_fast_unknown_ensures_fast_false (CVC5)
[wp] [Timeout] typed_hard_true_assert_fermat3 (CVC5)
--- three provers: console
[wp] [Timeout] typed_fast_unknown_ensures_fast_false (Alt-Ergo)
[wp] [Timeout] typed_hard_true_assert_fermat3 (Alt-Ergo)
--- three provers: -wp-status (every prover's answer is known)
      2 Prover Alt-Ergo 2.6.4 returns Timeout
      1 Prover CVC5 1.1.2 returns Timeout
      1 Prover CVC5 1.1.2 returns Unknown
      1 Prover Z3 4.13.3 returns Timeout
      1 Prover Z3 4.13.3 returns Unknown
--- three provers: r3.json, provers listed per goal
"goal":"typed_fast_unknown_ensures_fast_false" "prover":"qed" "time":0 "prover":"Alt-Ergo:2.6.4" "time":0
"goal":"typed_hard_true_assert_fermat3" "prover":"qed" "time":0.000774 "prover":"Alt-Ergo:2.6.4" "time":0
"goal":"typed_product_ensures_bounded" "prover":"qed" "time":0.00171 "prover":"Alt-Ergo:2.6.4" "time":0.0111
--- cache: second run with -wp-cache update, "cached" in the JSON
[wp] [Timeout] typed_fast_unknown_ensures_fast_false (Alt-Ergo) (Cached)
[wp] [Timeout] typed_hard_true_assert_fermat3 (Qed 0.68ms) (Alt-Ergo) (Cached)
[wp] [Cache] found:7
"goal":"typed_fast_unknown_ensures_fast_false" "cached":3 "goal":"typed_hard_true_assert_fermat3" "cached":3 "goal":"typed_product_ensures_bounded" "cached":1
RESULT: present (r3.json keeps one prover per goal, -wp-status saw three)
```

Prover answers on unproved goals depend on the machine: Timeout and Unknown can swap under load.
The loss of information does not.

## Related, not overlapping

- !42 / #2811 (probes drop goal variables): changes `cfgWP.ml` and the `wp_ce` tests. Nothing here
  touches those files.
- #2752 (counterexample prover variants, closed): prover selection, not reporting.
- #2787 (Why3 anomaly in `qed/term.ml`): unrelated.
- #2763 (`-wp-interactive` per prover) and #2675 (unclear CSV status) are near in topic but ask for
  something else.

## Workaround

The pipeline gives an unproved goal `time_ms: null` and fires its "too large" hint only with a
single prover (`scripts/run_wp_function.py`, see the troubleshooting entry). To get per-prover
answers today, it could parse `-wp-status`, which names each goal and lists every prover's
verdict. That parse is fragile, since the text is not a stable format.

## Tracker

Live search on 2026-11-17 (glab api, read-only) for `report-json`, `json report`, `msg-key prover`
and `Cached`: no match. The 2026-11-09 export
([`./pub-frama-c_work_items_2026-11-09.csv`](./pub-frama-c_work_items_2026-11-09.csv)) matches only
#2763, which is not the same request.
