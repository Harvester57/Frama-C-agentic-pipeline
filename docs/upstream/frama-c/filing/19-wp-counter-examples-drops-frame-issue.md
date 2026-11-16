# [WP] A probe (`-wp-counter-examples` or a `probe` annotation) makes a valid goal unprovable: the equality between unchanged memory states is dropped

<!-- Everything below this line is the issue description. -->

### Summary

Adding a probe, either a `probe` annotation or the probes that `-wp-counter-examples` generates, can make a valid goal unprovable. `ensures p->ptr == \old(p->ptr);` on a function that never writes `p->ptr` goes from `Prove: true` to `Prove: Mptr_0[a] = Mptr_1[a]`, with nothing relating the two memories. Enabling counter-examples therefore changes the verdict of valid goals.

### Steps to reproduce the issue

`t.c`:

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

```
$ B="frama-c -no-unicode t.c -wp -wp-fct buf_reset -wp-prop keep_ptr -wp-cache none"
$ $B -wp-prover none -wp-print
$ $B -wp-prover none -wp-print -wp-counter-examples
$ $B -wp-prover alt-ergo -wp-timeout 5 -wp-counter-examples
$ $B -wp-prover z3,cvc5 -wp-timeout 5 -wp-counter-examples
```

The same happens without `-wp-counter-examples` when the function contains a probe annotation,
for instance `//@ probe P: p;` before `p->len = 0;`.

### Expected behaviour

`-wp-counter-examples` (and probes in general) should only add information to report models. The
goal `keep_ptr` is valid, the function never writes pointer memory, and without the option Qed
discharges it: `Prove: true.`. It should stay `Prove: true.` with the option or with a probe.

### Actual behaviour

Without the option:

```
Goal Post-condition 'keep_ptr' in 'buf_reset':
Prove: true.
```

With `-wp-counter-examples`:

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

Nothing relates `Mptr_1` to `Mptr_0`, so no prover can close it:

```
[wp] [Timeout] typed_buf_reset_ensures_keep_ptr (Qed 2ms) (Alt-Ergo)
[wp] [Unknown] typed_buf_reset_ensures_keep_ptr (Qed 0.66ms) (Z3) (Model)
```

Z3 and CVC5 return `Unknown` with a model, which is spurious, so a user reading the
counter-example is led to a bug that does not exist. With `//@ probe P: p;` and no option, the goal
is the same (`Probe P = p.` instead of `Probe p = p.`) and Alt-Ergo times out too.

With `-wp-no-let` the missing hypothesis is visible. Without the option:

```
  Have: (Mptr_0 = Mptr_1) /\ (p_1 = p).
```

With the option, only `Have: p_1 = p.` is left: the memory equality is gone, the equality on the
probed variable `p` is kept.

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at 3dff90fc70; also 34.0~beta (Selenium), same output
- Plug-in used: WP (Alt-Ergo 2.4.3, Z3, CVC5)
- OS name: Debian GNU/Linux
- OS version: 13 (trixie)

### Additional information (optional)

Cause, on `3dff90fc70`, `plugins/wp/src/cfgWP.ml`: `probe_vc` (lines 290-301) builds the new VC
with `vars = F.vars term` (line 291), the variables of the probed term only, and drops `vc.vars`,
the free variables of the goal. `assume_vc` keeps `vc.vars`. These variables are what `passify_vc`
(lines 406-408) uses, through `occurs_vc` (lines 246-247), to keep the passive equalities of a
label or merge: once a probe was added, `Mptr_1` no longer "occurs" (it is only in the goal), so
`Mptr_0 = Mptr_1` is dropped, while `p_1 = p` survives because `p` is in the probe. Every probe
goes through `probe_vc`: the formals probed by `-wp-counter-examples` (`do_probe_formal`,
`plugins/wp/src/cfgCalculus.ml:473-478`) and the user `probe` annotations (`cfgCalculus.ml:233`).

Fix: `let vars = V.union (F.vars term) vc.vars in`. With it, the goal is `Prove: true.` again in
both cases (Qed, 1/1), the `-wp-no-let` output has `Have: (Mptr_0 = Mptr_1) /\ (p_1 = p).` back, and
goals that genuinely fail still get a model (`ensures p->len == 1;` gives `[Unknown] ... (CVC5)
(Model)`, as before).

Related: #2787 (CVC5 fails with a Why3 anomaly under `-wp-counter-examples` instead of timing out)
is another case where the option changes the outcome, but a different symptom (a crash on a hard
goal, not a dropped hypothesis on a trivial one). #2752 (the `-ce` prover variants not found in
`why3.conf`, closed) is about prover names and is unrelated.

A merge request with a fix follows.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
