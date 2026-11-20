# `\result` is refused in a `\postcond` property

<!-- Everything below this line is the issue description. Tracker: pub/meta (MetAcsl), not pub/frama-c. -->

### Summary

A property with `\context(\postcond)` becomes an `ensures` clause of each target function, but
its predicate cannot use `\result`: MetAcsl stops with `\result meaningless`. A property that
relates the returned value to the state ("when the function fails, the state is unchanged")
can therefore not be written as a meta-property. This is a feature request, unless the
restriction is intended; I did not find it in the README.

### Steps to reproduce the issue

`login.c`:

```c
int auth_ok;

int login(int pw)
{
  if (pw != 42)
    return -1;
  auth_ok = 1;
  return 0;
}

/*@ meta \prop, \name(unchanged_on_failure), \targets({login}), \context(\postcond),
      \result != 0 ==> auth_ok == \old(auth_ok);
*/
```

```
$ frama-c login.c -meta -then-last -print
```

### Expected behaviour

`login` gets the clause

```
/*@ ensures unchanged_on_failure: meta: \result != 0 ==> auth_ok == \old(auth_ok); */
```

as it does for a predicate without `\result` (`auth_ok == \old(auth_ok) || auth_ok == 1` gives
`ensures unchanged_on_failure: meta: auth_ok ≡ \old(auth_ok) ∨ auth_ok ≡ 1;`).

### Actual behaviour

```
[meta] Translation is enabled
[meta] Will process 1 properties
[meta] User Error: Error during the typing of a HILARE!
  What:        the HILARE named 'unchanged_on_failure' (login.c:11)
  Where:       in function 'login', at login.c:11
  Why:         \result meaningless
  Environment: there were no meta-variables.
[kernel] Plug-in meta aborted: invalid user input.
```

### Contextual information

- Frama-C installation mode: opam (Docker image)
- Frama-C version: 34.0~beta (Selenium), with MetAcsl 0.12~beta
- MetAcsl `master` (`4f43801390`): reproduced (built against the installed 34.0~beta kernel, minus
  `master`'s one `PLpointer_comparable` case in `meta_parse.ml`).
- OS name: Debian GNU/Linux
- OS version: 13 (trixie)

### Additional information (optional)

- **Where it comes from, as far as I can tell.** The kernel types `\result` by looking the
  variable up in the logic environment (`Logic_typing`, the `PLresult` case), and reports
  `\result meaningless` when it is absent. `process_meta_termassoc` in `meta_parse.ml` builds
  the environment of every property from `append_here_label`, `append_pre_label` and
  `append_old_and_post_labels`, whatever the context, and nothing calls
  `Logic_typing.add_result`.
- **A possible change.** Pass `~with_result:(mp_context = Postcond)` from `process_property`
  through `delay_prop` to `process_meta_termassoc` and, when set and
  `Ast_types.C.is_fun (Kernel_function.get_type kf)` holds (guarding against
  `Cil_datatype.Kf.dummy` used by `Meta_deduce.dummy_unpack`, whose type is `Typ.dummy`), extend
  the environment with `Logic_typing.add_result env (Ctype rt)` where `rt` is
  `Kernel_function.get_return_type kf` (with `Ast_types.C.add_ghost` when
  `Kernel_function.is_ghost kf`, matching `Logic_typing.funspec` and `Filecheck.check_ast`).
  `add_result` leaves the environment unchanged for a function that returns `void`, so `\result`
  stays an error there (and collapses to `\true` / `\false` under `\tguard` / `\fguard`).
  `\conditional_invariant` and all other non-`\postcond` contexts stay out, since their predicates
  are placed in clauses or assertions where `\result` has no meaning. I built and validated this
  change on `master` `4f43801390` (reproducer, edge cases, `tests/meta` and `tests/meta-wp` in
  both default and `fold` configurations); I will send it as a merge request with a regression
  test.
- **`\tguard` is not a way around it.** With the predicate under `\tguard`, the typing error
  makes the property `\true`, as the README says it does:

  ```
  /*@ meta \prop, \name(unchanged_on_failure), \targets({login}), \context(\postcond),
        \tguard(\result != 0 ==> auth_ok == \old(auth_ok));
  */
  ```

  gives `ensures unchanged_on_failure: meta: \true;`, and WP proves it (3 goals out of 3) for a
  `login` that sets `auth_ok` before its check. The same clause written by hand as an `ensures`
  of that function is not proved (2 out of 3). This is the documented behaviour of `\tguard`; I
  mention it because a user who meets the error above may reach for it.
- **What I do today.** The property is checked by an annotation written in the function's code,
  outside MetAcsl.

The analysis was prepared with LLM assistance (Claude Code); I reviewed it and ran the
reproducer described above.
