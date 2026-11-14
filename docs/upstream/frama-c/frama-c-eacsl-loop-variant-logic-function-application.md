# E-ACSL: a `loop variant` that is exactly one application of a memory-reading logic function aborts with `typing was not performed on construct f(s)`

Draft for the Frama-C tracker (https://git.frama-c.com/pub/frama-c/-/issues). Issue 16 of this
folder and of the master catalog
([`./frama-c-e-acsl-issues.md`](./frama-c-e-acsl-issues.md)).

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

## Versions

| | Result |
|---|---|
| `34.0~beta (Selenium)`, opam build, image `framac-analysis:latest` (2026-11-14) | **aborts** |
| `35.0~~dev (Bromine)`, local image `framac-analysis:fc35dev` | **aborts** |

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

Not confirmed by patching the plug-in.

## Expected

The variant is translated (or reported as not yet supported and ignored, as `loop variant using GMP`
is), without an internal error. A possible fix is to normalize the term in
`Loops.handle_annotations` before typing it:

```ocaml
let t = Logic_normalizer.get_term t in
Typing.preprocess_term ~use_gmp_opt:true ~logic_env t;
let ty = Typing.get_typ ~logic_env t in
```

or to have the `Typing` getters (`get_number_ty`, `get_cast`, ...) call `Logic_normalizer.get_term`
as `type_term` does. Only the second form also covers the `\let` site (`Translate_utils.env_of_li`).
Not built or tested.

## Workaround

Make the application a strict subterm: `loop variant len(s) + 0;`. With a function typed `integer`
and defined recursively the variant is then ignored (`loop variant using GMP` is not yet supported),
so nothing is checked at run time; with a C result type (`logic unsigned long len(char *s) = ...`)
it is translated and checked.

## Tracker

Not filed. No issue in the 2026-11-09 export
([`./pub-frama-c_work_items_2026-11-09.csv`](./pub-frama-c_work_items_2026-11-09.csv)) contains
`typing was not performed`.
