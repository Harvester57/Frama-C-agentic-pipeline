# WP: `-wp-counter-examples` (or any `probe`) makes a postcondition on unwritten memory unprovable (the before and after memories are no longer related)

**Filed upstream on 2026-11-15:** issue [#2811](https://git.frama-c.com/pub/frama-c/-/work_items/2811), merge request [!42](https://git.frama-c.com/pub/frama-c/-/merge_requests/42).

Draft for the Frama-C tracker (https://git.frama-c.com/pub/frama-c/-/issues). Issue 19 of this
folder and of the master catalog
([`./frama-c-e-acsl-issues.md`](./frama-c-e-acsl-issues.md)).

**Filing package:** [issue](./filing/19-wp-counter-examples-drops-frame-issue.md), [MR](./filing/19-wp-counter-examples-drops-frame-mr.md), [reproducer](./repro/19-wp-counter-examples-drops-frame.sh), [patch](./patches/19-wp-counter-examples-drops-frame.patch)

## Summary

A postcondition stating that a memory location the function does not write keeps its value is
discharged by Qed (`Prove: true.`) in a normal WP run. With `-wp-counter-examples`, the same goal
becomes `Prove: Mptr_0[a] = Mptr_1[a].`, with no hypothesis relating the pre-state memory `Mptr_0`
to the post-state memory `Mptr_1`. No prover can close it:

- Alt-Ergo times out.
- Z3 and CVC5 return `Unknown` with a model, which is spurious.

So enabling counter-examples, which should only add witness models for goals that fail, changes the
verdict of a goal that is valid. The option is not needed: a single `probe` annotation in the
function has the same effect, because both go through the same code (see [Analysis](#analysis)).

Found 2026-11-15 in QCBOR `run-6`
([`../../runs/2026-11-14-qcbor-run6-supervision.md`](../../runs/2026-11-14-qcbor-run6-supervision.md)).
The pipeline re-checked merged contracts with `-wp-counter-examples`, and refused two contracts the
provers had fully proved:

- `UsefulOutBuf_Reset`, `ensures keep_UB_ptr: pUOutBuf->UB.ptr == \old(pUOutBuf->UB.ptr)`;
- `UsefulInputBuf_GetError`, `ensures keep_buffer`.

## Versions

| | Result |
|---|---|
| `35.0~~dev (Bromine)`, `master` at `3dff90fc70` (image `framac-master-audit:3dff90f`, 2026-11-15), Alt-Ergo 2.4.3, Z3, CVC5 | **goal unprovable with `-wp-counter-examples` or a `probe`, proved by Qed without** |
| `34.0~beta (Selenium)`, opam build, image `framac-analysis:fc34` (2026-11-15), Alt-Ergo, Z3, CVC5 1.1.2 | same, identical goals |

The code at fault dates from `7d407bcea7` ("[wp] compute all probes during calculus", 2024-01-22),
which gave `probe_vc` its current form; older releases were not checked.

## Reproduction

[`./repro/19-wp-counter-examples-drops-frame.c`](./repro/19-wp-counter-examples-drops-frame.c)
(no probe; uses the option) and
[`./repro/19-wp-counter-examples-drops-frame-probe.c`](./repro/19-wp-counter-examples-drops-frame-probe.c)
(same function with `//@ probe P: p;`, no option):

```c
typedef struct {
  const void *ptr;
  unsigned long len;
  int err;
} buf;

/*@ requires \valid(p);
    assigns p->len, p->err;
    ensures keep_ptr: p->ptr == \old(p->ptr);
    ensures reset: p->len == 0 && p->err == 0;
*/
void buf_reset(buf *p)
{
  p->len = 0;
  p->err = 0;
}
```

[`./repro/19-wp-counter-examples-drops-frame.sh`](./repro/19-wp-counter-examples-drops-frame.sh),
on master `3dff90fc70` (34.0~beta prints the same):

```
##### 19-wp-counter-examples-drops-frame.c (no option)
Prove: true.
##### 19-wp-counter-examples-drops-frame.c -wp-counter-examples
Prove: Mptr_0[a] = Mptr_1[a].
[wp] [Timeout] typed_buf_reset_ensures_keep_ptr (Qed 2ms) (Alt-Ergo)
##### 19-wp-counter-examples-drops-frame-probe.c (no option)
Prove: Mptr_0[a] = Mptr_1[a].
[wp] [Timeout] typed_buf_reset_ensures_keep_ptr (Qed 2ms) (Alt-Ergo)
RESULT: bug present
```

The full goal with the option:

```
Goal Post-condition 'keep_ptr' in 'buf_reset':
Let a = shiftfield_F1_ptr(p).
Assume {
  (* Heap *)
  Type: (region(p.base) <= 0) /\ linked(Malloc_0) /\ framed(Mptr_0).
  (* Pre-condition *)
  Have: valid_rw(Malloc_0, p, 3).
  Probe p = p.
}
Prove: Mptr_0[a] = Mptr_1[a].
```

With Z3 the result is `[Unknown] ... (Z3) (Model)`, after a series of
`Warning: Error while interpreting Mptr: The function k!0 cannot be converted into an array type`.

## Analysis

`-wp-no-let` shows the hypothesis that disappears. Without the option:

```
  Have: (Mptr_0 = Mptr_1) /\ (p_1 = p).
```

With the option, only `Have: p_1 = p.` is left. The memory equality is dropped, the equality on the
probed formal `p` is kept.

In `plugins/wp/src/cfgWP.ml` on `3dff90fc70`, `probe_vc` (lines 290-301) builds the new VC with
`vars = F.vars term` (line 291): the variables of the probed term only. It drops `vc.vars`, the free
variables of the goal, which `assume_vc` keeps. `passify_vc` (lines 406-408) decides which passive
equalities of a label or merge to keep with `occurs_vc` (lines 246-247): a variable is relevant if
it is in `vc.vars` or occurs in the hypotheses. After a probe, `Mptr_1` occurs only in the goal, so
`Mptr_0 = Mptr_1` is discarded; `p_1 = p` stays because `p` is in the probe.

Every probe goes through `probe_vc` (via `add_probe`, lines 522-533): the formals probed by
`-wp-counter-examples` (`do_probe_formal`, `plugins/wp/src/cfgCalculus.ml:473-478`) and the user
`probe` annotations (`cfgCalculus.ml:233`). That is why a single annotation, without the option, is
enough.

The pattern hits any postcondition that preserves memory of a type the function never writes, here
a `void *` member next to written integer members.

## Expected

Probes, and so `-wp-counter-examples`, should not change which goals are provable. The goal keeps
the relation between unchanged memory states and still reduces to `Prove: true.`.

## Fix

[`./patches/19-wp-counter-examples-drops-frame.patch`](./patches/19-wp-counter-examples-drops-frame.patch),
one commit on `fix/wp-probe-keeps-vars` from `3dff90fc70`, "[wp] probes must not drop the
variables of the goal":

```diff
   let probe_vc ~loc ?descr ?stmt ?warn ~name term vc =
-    let vars = F.vars term in
+    let vars = V.union (F.vars term) vc.vars in
```

plus a regression test `plugins/wp/tests/wp_ce/probes_frame.i` (default configuration, run with and
without `-wp-counter-examples`; its second function has a `probe` annotation).

## Validation

Patched `3dff90fc70`, built and installed over the switch of a throwaway copy of
`framac-master-audit:3dff90f`.

| Check | `master` | Patched |
|---|---|---|
| `keep_ptr` with `-wp-counter-examples`, `-wp-print` | `Prove: Mptr_0[a] = Mptr_1[a].` | `Prove: true.` |
| `keep_ptr` with `-wp-counter-examples`, Alt-Ergo / Z3,CVC5 | Timeout / Unknown (Model) | Proved 1/1 (Qed) |
| `keep_ptr` with `//@ probe P: p;`, no option, Alt-Ergo | Timeout | Proved 1/1 (Qed) |
| `-wp-no-let -wp-counter-examples` | `Have: p_1 = p.` | `Have: (Mptr_0 = Mptr_1) /\ (p_1 = p).` |
| Genuinely false goals (`ensures p->len == 1;`, `ensures p->ptr != \old(p->ptr);`), Z3,CVC5 with the option | Unknown (Model) | Unknown (Model), models still produced |
| ptests `@plugins/wp/tests/ptests_config`, default configuration (426 results) | — | pass; only the two new `probes_frame` oracles, no existing oracle changed |
| `qualif` / `ce` configurations | — | not run (no WP cache; `cvc4_ce.i` needs CVC4) |
| `dune build --profile dev @plugins/wp/check` | — | exit 0, no output |
| `git diff --check` | — | clean |

## Workaround

Decide the verdict from a run without `-wp-counter-examples`. Then rerun only the goals that failed
with the option, to collect models, and treat those models as hints. The pipeline does this since
branch `sup/QCBOR-wp-counterexample-false-unknown`
([`../../troubleshooting/wp-and-guardrail.md`](../../troubleshooting/wp-and-guardrail.md)). Avoid
`probe` annotations in contracts whose verdict matters.

## Tracker

Not filed at the time of writing (see the filing note at the top). In the 2026-11-09 export
([`./pub-frama-c_work_items_2026-11-09.csv`](./pub-frama-c_work_items_2026-11-09.csv)), the only
`-wp-counter-examples` item is #2787 (`[Why3 Error] anomaly: File "src/libraries/qed/term.ml"`).
In #2787, CVC5 fails with a Why3 anomaly under the option instead of timing out. It is a different
symptom: a crash on a goal that is hard anyway. Mention it as related. A live search on 2026-11-15
also found #2752 ("[Wp] Countexample variants of provers not usable", closed 2025-12-17): the
`cvc5-ce`-style prover names were not found in `why3.conf`. That is about prover selection, not
about the generated goals; the issue text says it is distinct.
