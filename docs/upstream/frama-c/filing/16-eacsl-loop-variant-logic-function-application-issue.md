# [E-ACSL] "typing was not performed" on a memory-reading logic function application in a loop variant or a `\let`

<!-- Everything below this line is the issue description. -->

### Summary

E-ACSL aborts with "typing was not performed on construct len(s)" when a loop variant is exactly one application of a logic function that reads memory (`loop variant len(s);`), and when such an application is bound by `\let`. The same application elsewhere in annotations is translated.

### Steps to reproduce the issue

`variant.c`:

```c
/* len3(s) is the length of s, up to 3. */
/*@ logic integer len3(char *s) =
      s[0] == '\0' ? 0 : s[1] == '\0' ? 1 : s[2] == '\0' ? 2 : 3; */

int walk(char *s) {
  int n = 0;
  /*@ loop variant len3(s); */
  while (*s) {
    s++;
    n++;
  }
  return n;
}

int main(void) {
  char buf[4] = "abc";
  return walk(buf) == 3 ? 0 : 1;
}
```

```
$ e-acsl-gcc -c -O prog variant.c
```

The same program with `/*@ loop variant \let k = len3(s); k; */` fails the same way.

### Expected behaviour

The variant is translated and checked. `prog.e-acsl` exits with 0 (`len3(s)` goes 3, 2, 1 and
stays non-negative).

### Actual behaviour

```
[e-acsl] Failure: typing was not performed on construct len3(s)
[kernel] Plug-in e-acsl aborted: internal error (typing was not performed on construct len3(s)).
e-acsl-gcc: fatal error: aborted by Frama-C
```

With `-debug 1`, the backtrace goes through `E_ACSL__Typing.get_number_ty` (`typing.ml:913`) and
`E_ACSL__Loops.handle_annotations` (`loops.ml:59`), or `E_ACSL__Translate_utils.env_of_li`
(`translate_utils.ml:249`) for the `\let` variant.

Only applications of a logic function whose body reads memory are affected, and only when the
application is the whole variant term or is bound by `\let`. `loop variant len3(s) + 0;` is
translated, and so is `len3(s)` in an `assert`, a `requires`, an `ensures` or a `loop invariant`.
An `assert \let k = len3(s); k >= 0;` aborts the same way, through `env_of_li`.

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at 3dff90fc70; also 34.0~beta (Selenium)
- Plug-in used: E-ACSL (`e-acsl-gcc`, default options; `frama-c -e-acsl` gives the same error)
- OS name: Debian GNU/Linux
- OS version: 13 (trixie)

### Additional information (optional)

`Logic_normalizer` replaces an application whose labels are all `Here` by an application of a copy
of the function specialized for `Here` (`Here_inliner`,
`plugins/e-acsl/src/analyses/logic_normalizer.ml:122`). A function whose body reads memory has such
a label. `Typing.type_term` starts with `let t = Logic_normalizer.get_term t in`
(`plugins/e-acsl/src/analyses/typing.ml:689`) and memoizes the type under the normalized term. The
getters `get_number_ty`, `get_cast` and `get_effective_ty` (`typing.ml:911-945`) look up the term
they are given without normalizing it. Most callers pass a normalized term (`Translate_terms.to_exp`
normalizes first), but two do not:

- `Loops.handle_annotations` (`plugins/e-acsl/src/code_generator/loops.ml:57-59`) types the variant
  term and then calls `Typing.get_typ` on the original term;
- `Translate_utils.env_of_li` (`plugins/e-acsl/src/code_generator/translate_utils.ml:244-249`)
  calls `Typing.get_typ` on the term bound by the `\let`.

When the application is a strict subterm (`len3(s) + 0`), the top-level term is not replaced, so
its lookup succeeds.

Fix: normalize the term in the typing getters, as `Interval.get_from_profile`
(`plugins/e-acsl/src/analyses/interval.ml:906-907`) already does. A term that the normalizer does
not replace is looked up as before. With this change, both programs build and `prog.e-acsl` exits
with 0, and a variant that does not decrease is reported at run time (`Variant failed`). The
`assert \let` above no longer aborts: it gets the existing warning
``E-ACSL construct `function application' is not yet supported`` and is ignored: the
memory-tracking analysis does not handle a function application bound by `\let`
(`plugins/e-acsl/src/analyses/memory_tracking.ml:375`). That limitation is separate. The E-ACSL
test suites (default and `dev` configurations; `format` in the default configuration only, see the
merge request) pass with no change to existing oracles. A merge request with a fix follows.

Workaround: make the application a strict subterm, as in `loop variant len3(s) + 0;`.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
