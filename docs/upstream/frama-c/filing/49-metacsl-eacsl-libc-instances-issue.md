# [MetAcsl] E-ACSL builds: a `memcpy` into a `\writing`-protected global gets no instance and no warning, and an overflowing `memcpy` is reported at `<unknown>:0`

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
   `<unknown>:0: Error: E-ACSL RTE failed`.

### Steps to reproduce the issue

`copy.c`:

```c
#include <string.h>

int auth_ok;
char out[4];

#ifdef USER_CONTRACT
/* What the Frama-C libc says about memcpy, assigns and from only. */
/*@ assigns ((char *)d)[0 .. n - 1] \from ((char *)s)[0 .. n - 1];
    assigns \result \from d; */
extern void *memcpy(void *restrict d, const void *restrict s, size_t n);
#endif

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

int main(void)
{
  char buf[8] = "abcdefg";
  process(buf, sizeof buf);
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
$ e-acsl-gcc -M --libc-replacements -E "-DOVERFLOW -DBY_HAND" -c -o copy.frama.c -O copy copy.c && ./copy.e-acsl
```

### Expected behaviour

1. With the system headers, either the call gets its instance or MetAcsl warns that `memcpy` has
   no footprint and that the property is assumed there, as it does for a behavior without
   `assigns`.
2. The overflow is reported as it is without the property, or at least at a location in
   `copy.c`.

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
copy.c:39: Error: Assertion failed:
	The failing predicate is:
	auth_state/meta:
		\separated(
  (char *)((void *)(&auth_ok)) + (0 .. (unsigned long)4 - 1), &auth_ok
  ).
```

Point 2. Without the property, the overflow is reported by E-ACSL's `memcpy`:

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

`-L` instead of the contract gives the same `<unknown>:0` report. The same `\separated` written
by hand before the call (`-DOVERFLOW -DBY_HAND`, no property) is reported at its line:

```
copy.c: In function 'process'
copy.c:17: Error: E-ACSL RTE failed:
	The failing predicate is:
	memory access:
		\valid_read(&out[0 .. n - 1]).
```

### Proposal

1. **Warn on a call to a function without specification (merge request attached).** In
   `inspect_contract` (`meta_annotate.ml`), when the callee has no behavior at all, give the
   same warning as for a behavior without `assigns`, and give both a warning category,
   `no-footprint`, so that a user can silence it or make it an error. With the patch, the
   `-no-frama-c-stdlib` run above prints:

   ```
   [meta:no-footprint] Warning: 
     Cannot analyze footprint of function memcpy: no assigns clause. Assuming meta-properties with reading/writing contexts are valid in this function.
   ```

   `unknown-func` is not the right category: it is about names in `\targets`, and aborts by
   default.
2. **A location for the terms MetAcsl substitutes.** E-ACSL seems to take the location of a guard
   from the term it guards: the assertion written by hand is reported at `copy.c:17`, and in the
   `-L` build of point 1 the guard `\valid_read(&auth_ok)` of the instance has the line of the
   property while the guard of the range built from `memcpy`'s `assigns` has `<unknown>`, line 0
   (in the instrumented file). Giving the `\written` / `\read` terms built from a callee's
   contract the location of the call statement would make the report point at the call. A
   separate report, about `-meta-fold`, is about the location of the folded assertion itself
   (#ISSUE-48); this one is about terms inside an unfolded instance.
3. **An option for validity-guarded `\writing` / `\reading` instances.** Written by hand as
   `\valid(\written) ==> \separated(\written, &auth_ok)` (`-DGUARDED`), the overflow is reported
   by E-ACSL's `memcpy` again (`memcpy: insufficient space in destination space , at least 8
   bytes required`), and the write into `auth_ok` is still caught at `copy.c:35`. An option such
   as `-meta-guard-access` could produce `\valid(\written) ==> P` and `\valid_read(\read) ==> P`
   for a runtime back-end, leaving invalid accesses to the RTE and libc checks. It is a design
   choice: in this program the overflow also writes `auth_ok` (with `-e-acsl-no-rte-mem` the
   unguarded instance fails as `auth_state/meta` at `copy.c:39`), and the guarded form leaves
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
