# [E-ACSL] `<==>` over a labelled term aborts with "labels pre-analysis was not performed"

<!-- Everything below this line is the issue description. -->

### Summary

Translating `p1 <==> p2` aborts with "labels pre-analysis was not performed" when an operand contains a labelled term: `\old`, `\at`, or a formal parameter in a postcondition. So a common postcondition such as `ensures (\result != 0) <==> (b->n == 0);` cannot be instrumented at all. `34.0~~dev` translated it; `34.0~beta` and `master` do not.

### Steps to reproduce the issue

`iff.c`:

```c
struct s { int n; };

/* In a postcondition, the formal b stands for \old(b). */
/*@ requires \valid_read(b);
    assigns \nothing;
    ensures (\result != 0) <==> (b->n == 0); */
int f(struct s *b) { return b->n == 0; }

int main(void) { struct s x = { 0 }; return f(&x) - 1; }
```

```
$ e-acsl-gcc -c -O prog iff.c
```

An assertion with an explicit `\at` fails the same way (`iff_at.c`):

```c
struct s { int n; };

int f(struct s *b) {
  int r = b->n == 0;
  b->n = 5;
  /*@ assert (r != 0) <==> (\at(b->n, Pre) == 0); */
  return r;
}

int main(void) { struct s x = { 0 }; return f(&x) - 1; }
```

### Expected behaviour

The equivalence is translated and checked, as `(p1 ==> p2) && (p2 ==> p1)` is. Both programs build,
and `prog.e-acsl` exits with 0.

### Actual behaviour

The translation stops with an internal error:

```
[e-acsl] Failure: labels pre-analysis was not performed on construct \old(b)
[kernel] Plug-in e-acsl aborted: internal error (labels pre-analysis was not performed on construct \old(b)).
e-acsl-gcc: fatal error: aborted by Frama-C
```

and for `iff_at.c`:

```
[e-acsl] Failure: labels pre-analysis was not performed on construct \at(b->n,Pre)
```

Any `<==>` with an operand that contains `\old`, `\at`, or a formal in a postcondition fails. The
same predicate written as `(p1 ==> p2) && (p2 ==> p1)`, or an equivalence without labelled terms,
is translated.

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at 3dff90fc70; also 34.0~beta (Selenium)
- Plug-in used: E-ACSL (`e-acsl-gcc`, default options)
- OS name: Debian GNU/Linux
- OS version: 13 (trixie)

### Additional information (optional)

Outside interlang, `Piff` is translated in
`plugins/e-acsl/src/code_generator/translate_predicates.ml:177-189` by rewriting `p1 <==> p2`
into `(p1 ==> p2) && (p2' ==> p1')`, where `p1'` and `p2'` are deep copies
(`Terms.Id.deep_copy_predicate`, added in a9a91e590f so that the RTE analysis sees the second
occurrence of each operand). The copies get the RTE pre-analysis and typing, but not the labels
pre-analysis: `Labels.preprocess` (`plugins/e-acsl/src/analyses/labels.ml:549`) runs once over the
whole file and records labelled terms by identity. When the copy's `\old(b)` is translated,
`Labels.at_for_pot` (`labels.ml:106`) finds nothing, and `Translate_ats.to_exp`
(`translate_ats.ml:502`) raises the error.

Fix: in the rewriting, both operands are always evaluated (`p1` in the first conjunct; `p2` in the
first conjunct, or in the second one when `p1` is false). So `p1` and `p2` can be translated once
each and combined as `!e1 == !e2`, as the interlang translation of `Piff`
(`translate_predicates.ml:65`) already does. No copy is needed and each operand still gets its RTE
guards, once. With this change, both programs above build and `prog.e-acsl` exits with 0; the
E-ACSL test suites (default and `dev` configurations; `format` in the default configuration only,
see the merge request) pass, with one existing oracle updated (`memory/oracle/gen_objects.0.c`,
whose two `<==>` checks are now translated with each operand computed once). A merge request with a fix
follows.

Workaround: write `(p1 ==> p2) && (p2 ==> p1)`.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
