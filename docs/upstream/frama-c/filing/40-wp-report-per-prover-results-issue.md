# [WP] `-wp-report-json` keeps only the best prover per goal; per-prover verdicts and times are lost (and two manual inaccuracies)

<!-- Everything below this line is the issue description. -->

### Summary

With several provers (`-wp-prover alt-ergo,z3,cvc5`), WP keeps one result per goal: the best
prover's, in the order of `VCS.compare`. The `-wp-report-json` report and the console line show only
that one. On a goal that no prover proves, the other provers' answers cannot be read from any
machine-readable output: whether each gave Timeout or Unknown, and the time and steps it took.
`-wp-status` does print them, but as text.

This is a feature request: could the JSON report give each prover's result? Two sentences of the
manual about the same report are also inaccurate: the unit of `"time"`, and what `"cached"` counts.

### Steps to reproduce the issue

`t.c`:

```c
/*@ requires 0 <= x <= 100;
    ensures fast_false: \result > 50;   // false: x = 0
*/
int fast_unknown(int x) { return x; }

/*@ requires 0 <= x <= 100 && 0 <= y <= 100;
    ensures bounded: \result <= 10000;  // true, easy
*/
int product(int x, int y) { return x * y; }

/*@ requires 0 < a && 0 < b && 0 < c; */
void hard_true(int a, int b, int c)
{
  /*@ assert fermat3: a * a * a + b * b * b != c * c * c; */  // true, too hard
}
```

```
$ frama-c t.c -wp -wp-timeout 4 -wp-par 1 -wp-cache none -wp-prover cvc5
$ frama-c t.c -wp -wp-timeout 4 -wp-par 1 -wp-cache none -wp-prover alt-ergo,z3,cvc5 \
    -wp-report-json r3.json -wp-status
$ frama-c t.c -wp -wp-timeout 4 -wp-par 1 -wp-prover alt-ergo,z3,cvc5 \
    -wp-cache update -wp-cache-dir cache                       # twice, the second time with
                                                               # -wp-report-json c2.json
```

### Expected behaviour

The JSON report lets a tool see what each prover answered on each goal. On `fast_false`, for
example, CVC5 answers Unknown quickly (the goal is false or out of reach) while Alt-Ergo and Z3 time
out (a longer timeout might help).

The manual matches the report:

- `"time"` in the unit the manual gives;
- `"cached"` counting what the manual says.

### Actual behaviour

CVC5 alone:

```
[wp] [Unknown] typed_fast_unknown_ensures_fast_false (CVC5)
[wp] [Timeout] typed_hard_true_assert_fermat3 (Qed 1ms) (CVC5)
```

The three provers together print one line per goal:

```
[wp] [Timeout] typed_fast_unknown_ensures_fast_false (Qed 0.52ms) (Alt-Ergo)
[wp] [Timeout] typed_hard_true_assert_fermat3 (Qed 0.95ms) (Alt-Ergo)
```

`-wp-status` lists all three answers for each goal:

```
Prover Alt-Ergo 2.6.4 returns Timeout (Qed:0.52ms) (4s)
Prover CVC5 1.1.2 returns Unknown (Qed:0.52ms)
Prover Z3 4.13.3 returns Timeout (Qed:0.52ms) (4s)
[...]
Prover Alt-Ergo 2.6.4 returns Timeout (Qed:0.95ms) (4s)
Prover CVC5 1.1.2 returns Timeout (Qed:0.95ms) (4s)
Prover Z3 4.13.3 returns Unknown (Qed:0.95ms)
```

But `r3.json` keeps Qed plus Alt-Ergo only, with `"time": 0`:

```
{ "goal": "typed_fast_unknown_ensures_fast_false",
  ..., "verdict": "timeout",
  "provers": [ { "prover": "qed", "time": 0.000524, "success": 0 },
               { "prover": "Alt-Ergo:2.6.4", "time": 0, "success": 0 } ],
  "timeout": 1 },
```

On the proved goal `bounded`, `"time"` for Alt-Ergo is `0.00405`. That is in seconds: the prover
took about 4 ms.

On the second run with `-wp-cache update` (`[wp] [Cache] found:7`), the report has `"cached": 3`
for `fast_false` and `fermat3`, one per prover read from the cache, and `"cached": 1` for
`bounded`.

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at 95408044f7 (Alt-Ergo 2.6.4, Z3 4.13.3, CVC5 1.1.2); also 34.0~beta (Selenium) with Alt-Ergo 2.4.3, same behaviour
- Plug-in used: WP
- OS name: Debian GNU/Linux
- OS version: 13 (trixie)

### Additional information (optional)

Where it happens, on master:

- `Stats.results` (`Stats.ml:108-127`) keeps `Qed` plus the prover chosen by `VCS.best`.
  `VCS.compare` prefers a valid result, then a model, then the higher `vrank` (Timeout 4 >
  Unknown 3). So a Timeout hides a quicker Unknown.
- `Stats.presult` (`Stats.ml:80`) gives `pzero` to non-valid results. That explains `"time": 0` on
  unproved goals, which I understand is intended: the time is the proof time.
- `register.ml` `do_report_json` and `stats_to_json` write `ProofEngine.consolidated g`, while
  `Wpo.get_results g` still holds every prover's result.

**Feature request.** Could the JSON report carry the per-prover results? For example, a new
`"results": [ { "prover", "verdict", "time", "steps", "cached" } ]` per goal, built from
`Wpo.get_results`, with `"provers"` unchanged so that existing readers keep working. It could also
sit behind an option. If you prefer not to, a sentence in the manual saying that only the best
prover is reported, and pointing to `-wp-status`, would already help.

**Manual (`plugins/wp/doc/manual/wp_plugin.tex`):**

- Line 2302: `"time"` is described as "prover time, in milliseconds". The value is
  `prover_time`, in seconds (`0.00405` above). In another run with `-wp-msg-key prover`, the debug
  line printed `Valid (12ms)` for a goal that the JSON reported as `0.0123`.
- Lines 2315-2316: `"cached"` is "number of cached sub-goals verdicts (including Qed proved
  sub-goals)". It counts prover results read from the cache (`Stats.add_cached`), one per prover,
  and excludes Qed (`cacheable` requires `p <> Prover.Qed`). That is why one goal shows
  `"cached": 3` above.

I am sending a merge request for these two manual sentences only; the feature request above does
not depend on it.

Not reported as bugs, since the code shows they are intended:

- `(Cached)` printed on the run that fills the cache (`Stats.pp_stats`, `updating || cachemiss = 0`).
- The `prover` debug line of an Unknown answer has no time or steps
  (`ProverWhy3.ml:132-134`). I did not propose to change that one, since the result's time also
  feeds the cache.

The analysis was prepared with LLM assistance (Claude Code); I reviewed it and ran the reproducer
described above.
