# E-ACSL builds: a `memcpy` into a `\writing`-protected global gets no instance and no warning, and out-of-bounds writes are reported at `<unknown>:0`

<!-- Everything below this line is the issue description. Tracker: pub/meta (MetAcsl), not pub/frama-c. -->

### Summary

This is a feature request, with a small merge request for its first point. It comes from using
MetAcsl with E-ACSL as the back-end, through `e-acsl-gcc` (MetAcsl in a first stage, then
`-then-last`, E-ACSL).

1. `e-acsl-gcc` parses with the system headers (`-no-frama-c-stdlib`), so `memcpy`, `memset`,
   `strcpy` and the rest of the libc have no specification. A `\writing` property then gets no
   instance at `memcpy(&protected, ...)`, and MetAcsl says nothing: the README says a callee
   without footprint is assumed to respect the property, and the warning `Cannot analyze
   footprint of function ...` exists, but it is only given for a behavior without `assigns`. A
   function declared without any specification has no behavior, so it is skipped silently. The
   E-ACSL binary runs clean. With the Frama-C libc (plain `frama-c`, or `e-acsl-gcc -L`) the same
   call has its instance.
2. Once `memcpy` has an `assigns` clause, an overflowing `memcpy` is no longer reported by E-ACSL's
   `memcpy` check (`memcpy: insufficient space in destination space`). It stops earlier, in the
   validity guard E-ACSL puts on the `\separated` of the instance, and that guard has no location:
   `<unknown>:0: Error: E-ACSL RTE failed`. The same `<unknown>:0` guard failure also happens on an
   ordinary out-of-bounds C pointer write (`*p = 1`, with no libc and no callee contract), because
   `meta_annotate.ml` constructs every `\written`, `\read` and `\called` term without `~loc`.

### Steps to reproduce the issue

`copy.c`:

```c
#include <string.h>

int auth_ok;
char out[4];
int out_i[4];

#ifdef USER_CONTRACT
/* What the Frama-C libc says about memcpy, assigns and from only. */
/*@ assigns ((char *)d)[0 .. n - 1] \from ((char *)s)[0 .. n - 1];
    assigns \result \from d; */
extern void *memcpy(void *restrict d, const void *restrict s, size_t n);
#endif

#ifdef OVERFLOW_PTR
void process(int *p)
{
  *p = 1; /* ordinary out-of-bounds write, no libc and no callee contract */
}
#else
void process(const char *in, size_t n)
{
#ifdef OVERFLOW
#ifdef BY_HAND
  /*@ assert \separated((char *)out + (0 .. n - 1), &auth_ok); */
#endif
  memcpy(out, in, n); /* writes 8 bytes into a 4-byte array */
#else
  (void)n;
  memcpy(&auth_ok, in, sizeof auth_ok); /* writes the protected global */
#endif
}
#endif

int main(void)
{
#ifdef OVERFLOW_PTR
  process(out_i + 10);
#else
  char buf[8] = "abcdefg";
  process(buf, sizeof buf);
#endif
  return 0;
}

#ifdef GUARDED
/*@ meta \prop, \name(auth_state), \targets({process}), \context(\writing),
      \valid(\written) ==> \separated(\written, &auth_ok);
*/
#else
/*@ meta \prop, \name(auth_state), \targets({process}), \context(\writing),
      \separated(\written, &auth_ok);
*/
#endif
```

Point 1:

```
$ frama-c -machdep gcc_x86_64 copy.c -meta -then-last -print
$ frama-c -machdep gcc_x86_64 -no-frama-c-stdlib copy.c -meta -then-last -print
$ e-acsl-gcc -M --libc-replacements -F -meta --then-last -c -o copy.frama.c -O copy copy.c && ./copy.e-acsl
$ e-acsl-gcc -M --libc-replacements -L -F -meta --then-last -c -o copy.frama.c -O copy copy.c && ./copy.e-acsl
```

Point 2 (`-M` and `--libc-replacements` are needed for E-ACSL's own `memcpy` check):

```
$ e-acsl-gcc -M --libc-replacements -E -DOVERFLOW -c -o copy.frama.c -O copy copy.c && ./copy.e-acsl
$ e-acsl-gcc -M --libc-replacements -E "-DOVERFLOW -DUSER_CONTRACT" -F -meta --then-last -c -o copy.frama.c -O copy copy.c && ./copy.e-acsl
$ e-acsl-gcc -M --libc-replacements -E -DOVERFLOW_PTR -F -meta --then-last -c -o copy.frama.c -O copy copy.c && ./copy.e-acsl
$ e-acsl-gcc -M --libc-replacements -E "-DOVERFLOW -DBY_HAND" -c -o copy.frama.c -O copy copy.c && ./copy.e-acsl
```

### Expected behaviour

1. With the system headers, either the call gets its instance or MetAcsl warns (with the call-site
   location) that `memcpy` has no footprint and that the property is assumed there, as it does for
   a behavior without `assigns`.
2. The `memcpy` overflow is reported as it is without the property, or at least both the `memcpy`
   overflow and the plain `*p = 1` out-of-bounds write are reported at a location in `copy.c`.

### Actual behaviour

Point 1. With the Frama-C libc the instance is there:

```
[meta] Translation is enabled
[meta] Will process 1 properties
[meta] Successful translation
void process(char const *in, size_t n)
{
  /*@ assert
        auth_state: meta:
          \separated(
            (char *)((void *)(&auth_ok)) + (0 .. sizeof(int) - 1), &auth_ok
            );
  */
  memcpy((void *)(& auth_ok),(void const *)in,sizeof(auth_ok));
  return;
}
```

With `-no-frama-c-stdlib` it is not, and there is no warning:

```
[meta] Translation is enabled
[meta] Will process 1 properties
[meta] Successful translation
void process(char const *in, size_t n)
{
  memcpy((void *)(& auth_ok),(void const *)in,sizeof(auth_ok));
  return;
}
```

The `e-acsl-gcc` build exits 0 and so does the binary. With `-L`, the binary stops at the
property:

```
copy.c: In function 'process'
copy.c:51: Error: Assertion failed:
	The failing predicate is:
	auth_state/meta:
		\separated(
  (char *)((void *)(&auth_ok)) + (0 .. (unsigned long)4 - 1), &auth_ok
  ).
```

Point 2. Without the property, the `memcpy` overflow is reported by E-ACSL's `memcpy`:

```
memcpy: insufficient space in destination space , at least 8 bytes required
Aborted
```

With the contract and the property:

```
<unknown>: In function 'process'
<unknown>:0: Error: E-ACSL RTE failed:
	The failing predicate is:
	memory access:
		\valid_read((char *)((void *)(&(out[0]))) + (0 .. n - 1)).
	With values at failure point:
	- "memory access": \valid_read((char *)((void *)(&(out[0]))) + (0 .. n - 1)): 0
	- n: 8
	- sizeof(char): 1
	- &(out[0]): 0x64dc2ef6b274
	- size: 8
Aborted
```

`-L` instead of the contract gives the same `<unknown>:0` report. An ordinary out-of-bounds write
`*p = 1` (`-DOVERFLOW_PTR`, no libc and no callee contract) fails at `<unknown>:0` the same way
(and its `\aligned(p,4)` guard in the instrumented file also has `file = "<unknown>", line = 0`):

```
<unknown>: In function 'process'
<unknown>:0: Error: E-ACSL RTE failed:
	The failing predicate is:
	memory access:
		\valid_read(p).
	With values at failure point:
	- "memory access": \valid_read(p): 0
	- sizeof(int): 4
	- p: 0x6338741f6288
Aborted
```

The same `\separated` written by hand before the call (`-DOVERFLOW -DBY_HAND`, no property) is
reported at its line:

```
copy.c: In function 'process'
copy.c:24: Error: E-ACSL RTE failed:
	The failing predicate is:
	memory access:
		\valid_read(&out[0 .. n - 1]).
```

### Proposal

1. **Warn on a call to a function without specification (merge request attached).** In
   `inspect_contract` (`meta_annotate.ml`), when the callee has no behavior at all, emit the
   same warning as for a behavior without `assigns`; put all three missing-footprint warnings
   (no specification, behavior with `WritesAny`, and `reading_visitor#passthrough_from` `FromAny`,
   an `assigns` clause without `\from`) under a new warning category `no-footprint` so that a user
   can silence them (`-meta-warn-key no-footprint=inactive`) or make them fatal (`=error`); and
   pass the call-site statement location `~loc:(Cil_datatype.Stmt.loc stmt)` (with `~once:true`
   matching `FromAny`, and `~loc` matching the `Indirect call` warnings) so each warning identifies
   the call's file and line. With the patch, the `-no-frama-c-stdlib` run above prints:

   ```
   [meta:no-footprint] copy.c:29: Warning: 
     Cannot analyze footprint of function memcpy: no assigns clause. Assuming meta-properties with reading/writing contexts are valid in this function.
   ```

   `unknown-func` is not the right category: it is about names in `\targets`, and aborts by
   default.
2. **A location for the terms MetAcsl substitutes.** E-ACSL takes the location of a guard from the
   term it guards: the assertion written by hand is reported at `copy.c:24`, and in the `-L` build
   of point 1 the guard `\valid_read(&auth_ok)` has the line of the property while the guard of the
   `\written` term has `<unknown>`, line 0. In `meta_annotate.ml`, `addr_of_tlval` (lines 487-506,
   called for `\written`, `\lhost_written`, `\read`, `\lhost_read`, and `\called`) calls
   `Logic_utils.mk_logic_AddrOf` (and in the bitfield branch `Logic_utils.mk_cast`,
   `Logic_const.term`, and `Logic_const.tinteger`) without `~loc`, and `writing_instance` (line
   640) and `reading_instance` (line 729) also call `Logic_const.term (TLval ...)` without `~loc`.
   Both `mk_logic_AddrOf` and `Logic_const.term` default `~loc` to `Kernel.gen_loc` (which E-ACSL
   prints as `<unknown>:0`); in `mk_logic_AddrOf`, even the `TMem e, TNoOffset` case (`*p`) builds
   a fresh `Logic_const.term ~loc e.term_node e.term_type`, discarding `e.term_loc`. As a result,
   every `\written`, `\read`, and `\called` term — whether built from a plain C lvalue via
   `Logic_utils.lval_to_term_lval` (lines 685, 691, 766) or from a callee's `assigns`/`\from`
   contract — gets `Kernel.gen_loc`, unlike `\func` at line 371 which passes `~loc`
   (`Property.location ump.ump_ip`). Passing the statement location (`Cil_datatype.Stmt.loc stmt`)
   or the property location into `addr_of_tlval` and those `Logic_const.term` calls would locate
   every guard in `copy.c`. A separate report, about `-meta-fold`, is about the location of the
   folded assertion itself (#ISSUE-48); this one is about terms inside an unfolded instance.
3. **An option for validity-guarded `\writing` / `\reading` instances.** Written by hand as
   `\valid(\written) ==> \separated(\written, &auth_ok)` (`-DGUARDED`), the overflow is reported
   by E-ACSL's `memcpy` again (`memcpy: insufficient space in destination space , at least 8
   bytes required`), and the write into `auth_ok` is still caught at `copy.c:47`. An option such
   as `-meta-guard-access` could produce `\valid(\written) ==> P` and `\valid_read(\read) ==> P`
   for a runtime back-end, leaving invalid accesses to the RTE and libc checks. It is a design
   choice: in this program the overflow also writes `auth_ok` (with `-e-acsl-no-rte-mem` the
   unguarded instance fails as `auth_state/meta` at `copy.c:51`), and the guarded form leaves
   that case to the `memcpy` check.

For point 1 of the summary there is also an E-ACSL side, which I did not file separately:
`e-acsl-gcc -L` gives the libc contracts to MetAcsl, but E-ACSL then translates every libc
contract, which its user manual warns costs run time, and it aborts on contracts with an
unbounded range (pub/frama-c#2798: `strtok_r`, `getsockopt`, `wcschr`, ...). An `e-acsl-gcc` mode
that parses with the Frama-C libc for MetAcsl without instrumenting the libc contracts would
remove the need for hand-written contracts. Tell me if you prefer that as a separate issue on
`pub/frama-c`.

### Contextual information

- Frama-C installation mode: opam (Docker image)
- Frama-C version: 34.0~beta (Selenium), with MetAcsl 0.12~beta and `e-acsl-gcc` with gcc 14
- MetAcsl `master` (`4f43801390`): the installed `meta_annotate.ml` is the same file as on
  `master` (git blob `03447cfd`). The patch was built against `master` (with one line of
  `meta_parse.ml` removed for the 34.0~beta kernel, the `PLpointer_comparable` case) and the
  reproducer was run with it.
- OS name: Debian GNU/Linux
- OS version: 13 (trixie)

### Additional information (optional)

- **What I do today.** In the E-ACSL build only, the meta file is followed by hand-written
  `assigns` contracts for `memcpy`, `memmove`, `memset` and `strncpy`, and each `\writing`
  property is rewritten as `\valid(\written) ==> P` (each `\reading` one with `\valid_read`).
  This is what the two `-D` switches above do; it makes the protected write fail and keeps the
  overflow's report. It is a workaround for one libc, so I do not propose it.
- **`strcpy`.** A contract for `strcpy` with `strlen`-bounded `assigns` gives an instance that
  keeps the callee's `Old` label, and E-ACSL aborts on it (`invalid label 'Old'`); that is
  reported separately (#ISSUE-47).
- **Without `-M`.** With `--libc-replacements` and without `-M`, the correct
  `memcpy(&auth_ok, ...)` already aborts (`memcpy: destination space  space unallocated or
  cannot be written`), with or without properties. That is an E-ACSL question and is not part
  of this request; the commands above use `-M`.

The analysis was prepared with LLM assistance (Claude Code); I reviewed it and ran the
reproducer described above.
