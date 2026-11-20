# E-ACSL: an `\old` or `\at` Term Is Evaluated at Its Label Even When a Guard Makes It Unneeded

**Status:** draft, not filed, no package number. Filing is paused until the maintainers answer on
[#2832](https://git.frama-c.com/pub/frama-c/-/work_items/2832), see [`./README.md`](./README.md).
Listed in the annex of #2832 (ref `old-guard`) since 2026-11-20.

**Found on:** libmodbus `run-1`, 2026-11-18, candidate
`src/modbus-rtu.c#modbus_rtu_set_serial_mode::rte::2820aa2803`, which the run's crash verifier
rejected as an instrumentation artifact.

**Reassessed on 2026-11-18** by the session that ran the hunt of that day: confirmed, with default
options, on `34.0~beta` (`framac-analysis:latest`) and on `master` `b80fcac74f`
(`framac-master-audit:b80fcac`). The reassessment found it wider than first written (any `\at`
term, any guard, any runtime error), found the cause in the sources, found no duplicate on the
live tracker, and found one contract of Frama-C's own libc that has the shape. See
[Reassessment](#reassessment).

## Summary

A postcondition can protect a dereference with a guard on the pre-state pointer:

```c
/*@ ensures keep: \old(p) == \null || p->debug == \old(p->debug); */
```

For `p == NULL` the first disjunct holds, so the clause is true and the right side is not needed.
E-ACSL still evaluates `\old(p->debug)` when the function is entered, before the guard is known,
and stops the program with an RTE alarm on the valid call `f(NULL)`.

The E-ACSL reference manual says this clause is well defined: `||`, `&&`, `==>` and `?:` are lazy,
"their right members are evaluated only if required" (section "Semantics"), and a tool must
"ensure that an undefined term is never evaluated". So the alarm is a false one: a correct
program with a valid contract is stopped.

## Reproducer

```c
#include <stddef.h>

struct s {
  int pad;
  int debug;
};

/*@ ensures keep: \old(p) == \null || p->debug == \old(p->debug);
*/
int f(struct s *p)
{
  if (p == NULL)
    return -1;
  return 0;
}

int main(void)
{
  return f(NULL) == -1 ? 0 : 1;
}
```

```bash
e-acsl-gcc -c -O out eold_guard.c
```

```bash
./out.e-acsl
```

The first draft passed `-G clang -F -e-acsl-full-mtracking`. They are not needed: the default
command gives the same result.

## Observed

The same result on `34.0~beta` and on `master` `b80fcac74f`: exit code 134, with this message.

```text
eold_guard.c: In function 'f'
eold_guard.c:8: Error: E-ACSL RTE failed:
	The failing predicate is:
	memory access:
		\valid_read(&p->debug).
	With values at failure point:
	- "memory access": \valid_read(&p->debug): 0
	- sizeof(int): 4
	- &p->debug: 0x4
Aborted
```

## Expected

The program exits with 0. The clause holds for every call of `f`.

## Reassessment

### Other forms that fail the same way

Each was run with the default `e-acsl-gcc -c` on both versions, on a call that makes the guard
skip the term. Each ends with exit code 134 and an `E-ACSL RTE failed` message.

| Form | Clause | Call | Failing RTE |
| :-- | :-- | :-- | :-- |
| Implication | `ensures p != \null ==> p->debug == \old(p->debug);` | `f(NULL)` | `\valid_read(&p->debug)` |
| Behavior | `behavior ok: assumes p != \null; ensures p->debug == \old(p->debug);` | `f(NULL)` | `\valid_read(&p->debug)` |
| Arithmetic | `ensures \old(d) == 0 \|\| \result == \old(100 / d);` | `g(0)` | `division by zero: d ≢ 0` |
| Label in the body | `assert q == \null \|\| r == \at(*q, L);` | `h(NULL)` | `\valid_read(q)` |

So this is not about `\old`, pointers or disjunctions: any term under `\at` is evaluated at its
label with blocking RTE checks, whatever protects it at the place of use. The behavior form is
the usual way to write a contract for a function that accepts `NULL`.

The first two rows are the reproducer above with another contract. The other two inputs:

```c
/*@ ensures quot: \old(d) == 0 || \result == \old(100 / d);
*/
int g(int d)
{
  if (d == 0)
    return 0;
  return 100 / d;
}

int main(void)
{
  return g(0);
}
```

```c
#include <stddef.h>

int h(int *q)
{
  int r = 0;
L:
  if (q != NULL)
    r = *q;
  /*@ assert same: q == \null || r == \at(*q, L); */
  return r;
}

int main(void)
{
  return h(NULL);
}
```

### Frama-C's own libc has the shape

`recvfrom` in `share/libc/sys/socket.h` (line 471 to 473 on `master`):

```c
  ensures initialization:addrbuf:
          addrbuf != \null ==>
            \initialized(((char *)addrbuf+(0 .. \old(*addrbuf_len)-1)));
```

The contract allows `addrbuf == \null && addrbuf_len == \null`. With Frama-C's libc
(`e-acsl-gcc -L`), this program stops on both versions:

```c
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>

int main(void)
{
  char buf[16];
  ssize_t n = recvfrom(0, buf, sizeof(buf), MSG_DONTWAIT, NULL, NULL);
  printf("recvfrom returned %d\n", (int)n);
  return 0;
}
```

```text
FRAMAC_SHARE/libc/sys/socket.h:473: Error: E-ACSL RTE failed:
	The failing predicate is:
	memory access:
		\valid_read(addrbuf_len).
```

Compiled with gcc alone it prints `recvfrom returned -1` and exits with 0. Without `-L` the
contract is not used and the instrumented program runs. No pipeline script passes `-L` to
`e-acsl-gcc` (searched in `scripts/`; a comment in `build_callgraph_dag.py` says the E-ACSL
builds are against glibc), so the pipeline meets this only through the contracts it writes
itself.

### The manuals

- **Reference manual** (`plugins/e-acsl/doc/refman/speclang_modern.tex`): the section
  "Semantics" gives the lazy operators and the tool's duty quoted above. The section on `\at`
  adds two scoping rules (the label is reached before the place of use; a C left-value that
  defines a logic variable of the term does not change in between). Neither says that the term
  must be defined at the label whatever guards it. The section "Pre- and Post- state" holds the
  grammar of `\old` and `\result` and nothing else.
- **User manual** (`plugins/e-acsl/doc/userman`): "the E-ACSL plug-in prevents an undefined term
  from being evaluated. If an annotation contains such a term, E-ACSL will report a proper error
  at runtime". Its only uses of `\old` are two examples of contracts, and the chapter on
  limitations does not mention `\old`, `\at` or labels.
- **Changelog of the plug-in:** two entries name these constructs, "Improve translation of
  `\at()` terms and predicates" (2022-03-04) and the fix of #231 below. Neither states a limit.

All `.tex` files of both manuals were searched for `\old` and `\at`. So this is not a documented
limit. It is a difference between the plug-in and the semantics the reference manual gives.

### The live tracker

Searched on 2026-11-18 in titles and descriptions, all states, every page of results: `old`,
`old guard`, `old evaluated`, `old null`, `old undefined`, `old assumes`, `old behavior`,
`old RTE`, `RTE failed`, `pre-state`, `at undefined`, `labels`, `LoopEntry`. The tracker's search
returns nothing for `\at` or `lazy`. 256 issues matched; three are E-ACSL issues with `\old` or
`\at` in their text.

- #231 (closed in 2018): an out-of-scope variable for a quantified variable inside `\old`.
  Another defect.
- #2744 (closed in 2025): `\at(x, Init)` gave a wrong value because the `Init` label was not
  supported. Another defect.
- #2800: ours, the `<==>` over a labelled term.

No duplicate.

### The cause

Read in the sources of `master` `b80fcac74f`:

- `plugins/e-acsl/src/code_generator/injector.ml`, line 480: for each statement,
  `Translate_ats.for_stmt` translates every `\at` term whose label is that statement.
- `plugins/e-acsl/src/code_generator/translate_ats.ml`, `for_stmt` (line 446) calls
  `pretranslate_to_exp` (line 244), which translates the term in place, with its RTE guards, and
  stores the value in a new variable `__gen_e_acsl_at_N`.
- `to_exp` (line 502) then gives that variable at the place of use.

The generated wrapper shows it. Before the call:

```c
    /*@ assert E_ACSL: "memory access": \valid_read(&p->debug); */
    ...
    __gen_e_acsl_at = p->debug;
```

and after the call, where the guard is:

```c
    if (__gen_e_acsl_at_5 == (struct s *)0) __gen_e_acsl_or = 1;
    else {
      ...
      __gen_e_acsl_or = __gen_e_acsl_at_2->debug == __gen_e_acsl_at;
    }
```

The lazy `||` protects the read of the saved variable, not the evaluation that filled it.

### A possible fix

No patch was written. The guard cannot be moved to the label in general, because it may depend
on the post-state (`\result == -1 || ... \old(*p)`). What can be done at the label: evaluate the
RTE guard of the term without stopping, skip the evaluation when it fails, keep the answer in a
flag, and check the flag at the place of use, where the laziness of the enclosing operators
applies. The error is then reported only when the term is needed. This changes how every `\at`
is translated, so it is the maintainers' decision.

## Workaround

Put the guard inside `\old`, and keep the outer one:

```c
/*@ ensures keep: \old(p) == \null || p->debug == \old(p == \null ? 0 : p->debug); */
```

Checked on both versions with the default command: `f(NULL)` and `f(&x)` pass, and a function
with the same clause whose body runs `p->debug++;` is stopped with `Postcondition failed`, so
the clause still checks what it says.

## Severity

A false alarm, not a missed bug: E-ACSL stops a correct program. It needs no option, and the
contract shape is ordinary. Among our reports it sits with "a correct program fails at run time"
(#2797, #2801, #2802), below the findings where an analysis accepts something false.

## Where the Files Are

The eight inputs (`a.c` to `h.c`), the scripts `r1.sh` to `r5.sh` and their outputs for both
versions are in the scratch folder of the reassessing session, under `oldguard`. That folder is
not durable. The inputs of every failing form are in this text; the input of the workaround
check is described, not copied.
