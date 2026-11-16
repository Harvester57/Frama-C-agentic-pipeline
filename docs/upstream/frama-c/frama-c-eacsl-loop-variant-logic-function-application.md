# E-ACSL: a `loop variant` that is exactly one application of a memory-reading logic function aborts with `typing was not performed on construct f(s)`

**Filed upstream on 2026-11-15:** issue [#2806](https://git.frama-c.com/pub/frama-c/-/work_items/2806), merge request [!37](https://git.frama-c.com/pub/frama-c/-/merge_requests/37).

Draft for the Frama-C tracker (https://git.frama-c.com/pub/frama-c/-/issues). Issue 16 of this
folder and of the master catalog
([`./frama-c-e-acsl-issues.md`](./frama-c-e-acsl-issues.md)).

**Filing package:** [issue](./filing/16-eacsl-loop-variant-logic-function-application-issue.md), [MR](./filing/16-eacsl-loop-variant-logic-function-application-mr.md), [reproducer](./repro/16-eacsl-loop-variant-logic-function-application.sh), [patch](./patches/16-eacsl-loop-variant-logic-function-application.patch)

## Summary

When the term of a `loop variant` is, at top level, the application of a user-defined logic function
whose body reads memory (`loop variant len(s);` with `len` dereferencing `s`), E-ACSL aborts the
whole translation with an internal error:

```
[e-acsl] Failure: typing was not performed on construct len(s)
[kernel] Plug-in e-acsl aborted: internal error (typing was not performed on construct len(s)).
```

The same application is translated without error in an `assert`, a `requires`, an `ensures` or a
`loop invariant`, and inside a larger variant term (`loop variant len(s) + 0;`). A logic function
that does not read memory (`logic integer f(integer x) = x + 1;`, or a pointer parameter that the
body never dereferences) is not affected. The recursive definition of a string length is the natural
measure of a loop that walks a NUL-terminated string, so this is the first variant one writes for
such a loop.

The same cause hits a `\let` that binds such an application, in any annotation:
`loop variant \let k = len(s); k;` and `assert \let k = len(s); k >= 0;` abort with the same
message (through `Translate_utils.env_of_li`, see below), so the bug is not specific to loop
variants.

## Versions

| | Result |
|---|---|
| `35.0~~dev (Bromine)`, `master` at `3dff90fc70`, image `framac-master-audit:3dff90f` | **aborts** (plain and `\let` variants, `\let` in an `assert`) |
| `34.0~beta (Selenium)`, image `framac-analysis:fc34` | **aborts** (plain and `\let` variants) |
| `35.0~~dev (Bromine)`, older local image `framac-analysis:fc35dev` | **aborts** |

Not checked on 33.0.

## Reproduction

`repro.c` (no header, no option beyond `-e-acsl`):

```c
/*@ logic integer len(char *s) = s[0] == '\0' ? 0 : 1; */

int walk(const char *s)
{
    int n = 0;
    /*@ loop variant len(s); */
    while (*s) {
        s++;
        n++;
    }
    return n;
}

int main(void)
{
    char buf[4] = "abc";
    return walk(buf) == 3 ? 0 : 1;
}
```

```
$ frama-c repro.c -e-acsl -then-last -print -ocode out.c; echo rc=$?
[e-acsl] Failure: typing was not performed on construct len(s)
[kernel:backtrace]
  ...
  Called from E_ACSL__Typing.get_number_ty in file "plugins/e-acsl/src/analyses/typing.ml", line 921, characters 2-79
  Called from E_ACSL__Typing.get_typ in file "plugins/e-acsl/src/analyses/typing.ml" (inlined), line 936, characters 16-44
  Called from E_ACSL__Loops.handle_annotations.(fun) in file "plugins/e-acsl/src/code_generator/loops.ml", line 59, characters 22-49
  ...
[kernel] Plug-in e-acsl aborted: internal error (typing was not performed on construct len(s)).
rc=4
```

`-e-acsl-full-mtracking` and `-e-acsl-gmp-only` do not change the result.

Variations (34.0~beta, `walk` as above, `k` an `int` local decremented in the loop):

| Logic function | `loop variant f(..);` | `loop variant f(..) + 0;` |
|---|---|---|
| `logic integer f(char *s) = s[0] == '\0' ? 0 : 1 + f(s + 1);` (recursive, reads memory) | **aborts** | translated, variant ignored (`loop variant using GMP` not yet supported) |
| `logic integer f(char *s) = s[0] == '\0' ? 0 : 1;` (reads memory) | **aborts** | translated and checked |
| `logic unsigned long f(char *s) = ...` (C result type, reads memory, recursive or not) | **aborts** | translated and checked |
| `logic integer f(char *s) = 0;` (pointer parameter, no read) | translated and checked | translated and checked |
| `logic integer f(char *s, integer x) = x;` | translated and checked | translated and checked |
| `logic integer f(integer x) = x + 1;` | translated and checked | translated and checked |
| `logic integer f(integer x) = x <= 0 ? 0 : 1 + f(x - 1);` | translated, variant ignored (GMP) | translated, variant ignored (GMP) |

`loop variant \let n = f(s); n;` also aborts with the same message for the second and third
functions (with the first one the variant is ignored, GMP). With the first function, `/*@ assert f(s) >= 1; */`,
`/*@ loop invariant f(s) >= 0; */` and `requires f(s) >= 0; ensures f(\old(s)) >= 0;` are all
translated.

## Analysis

Sources of the installed 34.0~beta plug-in (`lib/frama-c-e-acsl/core/`).

`Loops.handle_annotations` (`code_generator/loops.ml:57-59`) types the variant and reads its type back
on the term stored in the environment:

```ocaml
Typing.preprocess_term ~use_gmp_opt:true ~logic_env t;
let ty = Typing.get_typ ~logic_env t in
```

`Logic_normalizer` replaces an application whose labels are all `Here` by an application of a
specialized copy of the function (`Here_inliner`, `analyses/logic_normalizer.ml:224-248`; a function
whose body reads memory carries such a label). `Typing.type_term` starts with
`let t = Logic_normalizer.get_term t in` (`analyses/typing.ml:691`), so the type is memoized for the
normalized term. `Typing.get_number_ty` (`typing.ml:919-921`) looks the original term up without
normalizing it, finds nothing, and `Error.retrieve_preprocessing` turns the `Not_memoized` into the
fatal error. When the application is a strict subterm (`f(s) + 0`), the top-level term is not
replaced and the lookup succeeds. `Translate_terms.to_exp` normalizes its argument itself, which is
why the other annotation kinds work.

The normalizer's debug output shows the replacement on `repro.c`:

```
$ frama-c repro.c -e-acsl -e-acsl-msg-key analysis:logic_normalizer -e-acsl-verbose 3 -e-acsl-debug 4
[e-acsl:analysis:logic_normalizer] inlining Here labels for term: len(s)
  memoised term  len(s)  as  __gen_e_acsl_len_here(s)
[e-acsl] Failure: typing was not performed on construct len(s) in phase `analysis:typing'
```

The `\let n = f(s); n` variant fails at a second site with the same cause, an un-normalized lookup
of the bound term:

```
Called from E_ACSL__Typing.get_typ in file "plugins/e-acsl/src/analyses/typing.ml" (inlined), line 936, characters 16-44
Called from E_ACSL__Translate_utils.env_of_li in file "plugins/e-acsl/src/code_generator/translate_utils.ml", line 249, characters 13-40
Called from E_ACSL__Translate_terms.context_insensitive_term_to_exp_old in file "plugins/e-acsl/src/code_generator/translate_terms.ml", line 940, characters 21-68
```

On `master` `3dff90fc70` the code is the same: `loops.ml:57-59`, `typing.ml:689` (`get_term` in
`type_term`), `typing.ml:911-945` (getters), `translate_utils.ml:244-249` (`env_of_li`). The
`-debug 1` backtraces on `master` go through `typing.ml:913` and `loops.ml:59` (plain variant), and
`translate_utils.ml:249` (`\let` variant). `Interval.get_from_profile` (`interval.ml:906-907`) already
normalizes before its lookup; the typing getters are the odd ones out. A third caller with the same
pattern is `Loops` at `loops.ml:405` (`Lvs_let`, the term of a `\let` inside a quantifier's logic
scope).

## Fix

Patch: [`./patches/16-eacsl-loop-variant-logic-function-application.patch`](./patches/16-eacsl-loop-variant-logic-function-application.patch)
(subject `[e-acsl] typing getters: look up the normalized term`, branch
`fix/eacsl-typing-getters-normalize` from `3dff90fc70`). In `plugins/e-acsl/src/analyses/typing.ml`,
a helper `get_info` normalizes the term with `Logic_normalizer.get_term` and then does the lookup;
`get_number_ty`, `get_cast` and `get_effective_ty` use it (`get_typ` and `get_effective_typ` go
through them). A term that the normalizer does not replace is looked up as before
(`Logic_normalizer.get_term` returns the term itself). This covers all callers at once, instead of
normalizing in `Loops.handle_annotations` only (the sketch of the previous version of this draft),
which would have left the `\let` sites. `Typing.unsafe_set`, the only other memoizer, has no caller.

Regression test `plugins/e-acsl/tests/constructs/logic_app_reading_memory.c`: `len3` (the length
of a string, up to 3, which reads memory) as a plain loop variant and as a `\let` variant, on a loop
where the variant does decrease, so the `dev` run exits 0. New oracles
`logic_app_reading_memory.0.res.oracle` and `gen_logic_app_reading_memory.0.c`.

After the fix, `assert \let k = len3(s); k >= 0;` no longer aborts: it is ignored with the existing
warning ``E-ACSL construct `function application' is not yet supported``, because the
memory-tracking analysis does not handle a function application bound by `\let`
(`memory_tracking.ml:375`, `register_term`). That limitation is separate and unchanged; the test
does not include this case.

## Validation

Built from `3dff90fc70` with the patch in a copy of `framac-master-audit:3dff90f`
(`dune build @install --release`, `dune install`). The reproducer
([`./repro/16-eacsl-loop-variant-logic-function-application.sh`](./repro/16-eacsl-loop-variant-logic-function-application.sh))
uses `len3` instead of the `len` above, so that the variant really decreases on `"abc"` and the
fixed build exits 0.

| Check | `master` | Patched |
|---|---|---|
| `loop variant len3(s);` | `Failure: typing was not performed on construct len3(s)` | builds, exit 0 |
| `loop variant \let k = len3(s); k;` | same failure | builds, exit 0 |
| `loop variant len3(t);` with `t` constant (does not decrease) | same failure | `Variant failed: (old len3(t)) > len3(t)`, exit 134 |
| `loop variant len3(s) + 0;` | builds, exit 0 | builds, exit 0 |
| `assert \let k = len3(s); k >= 0;` | same failure | ``E-ACSL construct `function application' is not yet supported``, annotation ignored, exit 0 |
| `constructs/logic_app_reading_memory.c`, default and `dev` | translation aborts | pass |
| ptests, every suite, default and `dev` configurations (`format`: default only, see below) | all pass | only difference: the new test (oracles added); then all pass |
| `ocp-indent` (opam, built-in configuration + `.ocp-indent`) on `typing.ml`; `clang-format` 19 on the test | | clean |
| `git diff --check` | | clean except the new oracles (trailing space after `Warning:`, trailing blank line: the ptests output format, as in every existing oracle) |
| `git apply --check` on `3dff90fc70` | | clean |

`format`: on `master` (unpatched) in this image, `format/printf.c` in the `dev` configuration stops
making progress after its 28th check and was killed after 90 minutes, so the `dev` configuration of
`format` was not compared; its default configuration matches the oracles on `master` and with the
patch.

## Workaround

Make the application a strict subterm: `loop variant len(s) + 0;`. With a function typed `integer`
and defined recursively the variant is then ignored (`loop variant using GMP` is not yet supported),
so nothing is checked at run time; with a C result type (`logic unsigned long len(char *s) = ...`)
it is translated and checked.

## Tracker

Not filed at the time of writing (see the filing note at the top). No issue in the 2026-11-09 export
([`./pub-frama-c_work_items_2026-11-09.csv`](./pub-frama-c_work_items_2026-11-09.csv)) contains
`typing was not performed`.
