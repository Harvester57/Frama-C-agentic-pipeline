# Discussion: priorities for the reports #2793 to #2831, and how to send further findings

<!-- Everything below this line is the issue description. -->

Between 15 and 18 November I opened 39 issues (#2793 to #2831) and 35 merge requests (!25 to !59).
That is a lot to receive at once from a new contributor. This issue says where the reports come
from, which ones I think matter, lists the findings I have not filed, and asks how you would like
me to continue. Please close it once it has served its purpose.

### Where the reports come from

I am building a pipeline that runs Frama-C on open-source C libraries without a human in the loop:
E-ACSL builds fuzzed with libFuzzer, then Eva, then WP. It uses options and combinations that few
users combine (full memory tracking with clang, `-warn-invalid-pointer` with E-ACSL, format-string
validation), which is why 27 of the 39 reports are about E-ACSL. Most reports are something the
pipeline hit on real code. The others were found while checking such a failure under other
options or reading the code around it: the two bittree reports (#2826, #2827) came that way, since
the pipeline itself uses the segment model. #2831 is different again: it started from a report on
the `frama-c-discuss` list, which the issue credits.

The analyses, reproducers and patches were prepared with LLM assistance (Claude Code), as each
text says. Each reproducer was run on `master` in a container, and again with the patch where
there is one. All 39 reports (#2793 to #2831) were also reproduced on `34.0~beta`. Each merge request lists
the test suites that were run on it.

### The ones I think matter

| Report | Component | Fix | Why |
| :-- | :-- | :-- | :-- |
| #2793 | E-ACSL | !25 | E-ACSL lets a false predicate pass at run time, with default options and an ordinary guarded quantifier. No warning. |
| #2800 | E-ACSL | !31 | `<==>` over `\old`, `\at` or a formal in a postcondition aborts the instrumentation. A 34.0 development build translated it; `34.0~beta` and `master` do not. |
| #2797 | E-ACSL | !28 | Closed issue #177 fails again: formal parameters are never marked initialized. |
| #2831 | WP | !59 | WP does not read hexadecimal floating-point literals: a hypothesis on `DBL_MAX` is dropped, and under `-wp-model +real` a suffixed literal is read as 0 (a wrong proof). |
| #2798, #2799 | E-ACSL, Libc | !29, !30 | An unbounded range aborts the whole E-ACSL instrumentation, and Frama-C's libc contracts contain some (`getsockopt`, `strtok_r`, four `wcs*` functions). |

Four more can give a wrong answer, in narrower settings:

- #2823: Eva's value for `__builtin_{add,sub,mul}_overflow` with mixed operand types differs from
  what gcc returns (no patch; the issue lists options).
- #2820: with `--validate-format-strings`, an invalid string after a `double` argument can go
  unchecked. #2822 shifts the checks in the same way after a `*` width or precision.
- #2826: with the bittree model, a local stays valid after its scope.

### What can wait

Next after those, four reject correct code with default options:

- #2802: `getenv` returns `NULL` in an instrumented program whose `main` takes `argc` and `argv`;
- #2805: an annotation on a pointer to an opaque struct gives code that does not compile;
- #2814: `struct sockaddr_in` is smaller than `struct sockaddr`, so Eva raises a false alarm;
- #2806: `loop variant len(s);` aborts the instrumentation.

The rest is an abort or a false alarm behind an option, a defect of the `e-acsl-gcc` wrapper or
of the pretty-printer, or a request (#2813, #2828, #2829 and #2830 are feature requests or header
additions; #2808 is a deprecated alias). I have no deadline on any of them. Feel free to close any
issue or merge request you do not want: one line is enough.

### Index by component

Every report I filed, with the merge request that fixes it. Three issues have no merge request
(#2815, #2816, #2823), and !26 closes two issues.

**E-ACSL (27)**

| Report | Fix | What happens | Kind |
| :-- | :-- | :-- | :-- |
| #2793 | !25 | In `\exists integer n; 0 <= n < size && P && Q`, only `Q` is checked, so a false predicate passes. | wrong verdict |
| #2795 | !26 | A monitored `const` union global: "implicit cast: cast from union u to void *". Same root cause as #2794. | the instrumentation aborts |
| #2798 | !29 | An unbounded range (`p + (0..)`) in any annotation, including the libc contracts used with `-L`, aborts the whole instrumentation. | the instrumentation aborts |
| #2800 | !31 | `<==>` over a labelled term: "labels pre-analysis was not performed". | the instrumentation aborts |
| #2804 | !35 | A `register` local under `-e-acsl-full-mtracking`: "Taking the address of a register variable". | the instrumentation aborts |
| #2805 | !36 | An annotation on a pointer to an opaque struct emits `sizeof` and `__alignof__` of the incomplete type. | the output does not compile |
| #2806 | !37 | "typing was not performed" on a memory-reading logic function in a loop variant or a `\let`. | the instrumentation aborts |
| #2816 | none | `Rtl.Symbols.Unregistered("__gmpz_clear")` when the program and an annotation both use GMP. The issue asks which fix you prefer. | the instrumentation aborts |
| #2794 | !26 | `__e_acsl_mark_readonly` gets the value of a `const` global instead of its address: "Use of invalid address" at start-up. | a correct program fails at run time |
| #2797 | !28 | Formal parameters are never marked initialized: `\initialized` on a by-value struct field or through `&formal` fails (#177 is back). | a correct program fails at run time |
| #2801 | !32 | With initialization checks, a postcondition reading a field of a struct `\result` fails on every call. | a correct program fails at run time |
| #2802 | !33 | When `main` takes `argc` and `argv`, `environ` is emptied: `getenv` always returns `NULL`. | a correct program fails at run time |
| #2803 | !34 | With `--libc-replacements`, `memcmp` on overlapping or identical buffers aborts. | a correct program fails at run time |
| #2815 | none | `--temporal`: a callee reads parameter metadata that its caller never saved ("Unreachable"). The issue asks which fix you prefer. | a correct program fails at run time |
| #2817 | !46 | `-e-acsl-full-mtracking` with clang: a literal stored inside another one makes `\valid_read` fail on correct code. | a correct program fails at run time |
| #2818 | !47 | `\object_pointer` is false on read-only data, so every `-warn-invalid-pointer` guard on it fails. | a correct program fails at run time |
| #2819 | !48 | `"%u"` or `"%x"` with an `unsigned char` or `unsigned short` argument aborts. | `--validate-format-strings` |
| #2820 | !49 | After a `double` or `long double` argument, `"%s"`, `"%p"` and `"%n"` are checked against the next argument. | `--validate-format-strings` |
| #2821 | !51 | Without `--full-mtracking`, every `printf` call aborts ("invalid format string"). | `--validate-format-strings` |
| #2822 | !50 | A `*` field width or precision makes every later directive be checked against the wrong argument. | `--validate-format-strings` |
| #2826 | !54 | `pt_lookup` returns an uninitialized pointer: every `free` aborts, and a program that stores no block crashes at exit. | bittree memory model |
| #2827 | !55 | `stdin`, `stdout`, `stderr` and `errno` are not safe locations, so run-time checks on them fail. | bittree memory model |
| #2807 | !38 | Option arguments are read again as options: `-e "-g -O1"` enables GMP and drops an input file. | `e-acsl-gcc` and options |
| #2808 | !39 | The deprecated `-e-acsl-assert-print-data` is an alias of `-e-acsl-O-valid` instead of `-e-acsl-O-print-values`. | `e-acsl-gcc` and options |
| #2809 | !40 | Frama-C preprocesses with `-D_DEFAULT_SOURCE` but the compiler does not: programs calling `strdup` or `stpcpy` fail to build. | `e-acsl-gcc` and options |
| #2810 | !41 | With `-G clang`, `CFLAGS` is overwritten: `-std=c99`, `-g`/`-O`, `-fno-builtin` and the warning flags are dropped. | `e-acsl-gcc` and options |
| #2825 | !53 | `--zone-sizes heap:2048` or `stack:2048` makes every run crash: the size overflows `int` when converted to bytes. | `e-acsl-gcc` and options |

**Kernel (4)**

| Report | Fix | What happens | Kind |
| :-- | :-- | :-- | :-- |
| #2796 | !27 | A variadic call in a local initializer is printed with the generated name (`open_fallback_1`). | the printed program does not link |
| #2812 | !43 | `_Alignas` is printed after the declarator of struct members and after `*` in pointer declarators. | the printed program does not compile |
| #2813 | !44 | `offsetof(T, m[i])` with a non-constant index (GCC and Clang extension) is rejected. | feature request |
| #2824 | !52 | `__restrict__` is a syntax error unless a Frama-C libc header is included. | valid code rejected |

**Libc (5)**

| Report | Fix | What happens | Kind |
| :-- | :-- | :-- | :-- |
| #2799 | !30 | `getsockopt`: the precondition `\valid(((char*)optval)+(0..))` cannot be satisfied: Eva rejects correct calls, WP aborts. | false alarm, abort |
| #2814 | !45 | `sockaddr_in` lacks `sin_zero` and is smaller than `struct sockaddr`; `struct ip_mreq` is missing; `fd_set` is not visible from `<sys/socket.h>`. | false alarm, header gap |
| #2823 | none | `__builtin_{add,sub,mul}_overflow`: wrong results for mixed operand types, parse error for small types, `_p` forms missing. The issue lists options. | wrong value |
| #2828 | !56 | Linux `<sys/epoll.h>` and `<sys/inotify.h>` are missing. | header addition |
| #2830 | !58 | `<sys/ioctl.h>` defines `TIOCMGET` and `TIOCMSET` but not the `TIOCM_*` modem line bits. | header addition |

**WP (3)**

| Report | Fix | What happens | Kind |
| :-- | :-- | :-- | :-- |
| #2811 | !42 | A probe (`-wp-counter-examples` or a `probe` annotation) makes a valid goal unprovable. | valid goal not proved |
| #2829 | !57 | `-wp-report-json` keeps only the best prover per goal. !57 fixes only the manual inaccuracies, not the report itself. | feature request |
| #2831 | !59 | Hexadecimal floating-point literals are not read: a hypothesis on `DBL_MAX` is dropped, and under `-wp-model +real` a suffixed one is read as 0. | wrong proof |

### Findings I have not filed

After #2831 I looked for the same kinds of mistake elsewhere: a literal read by a second parser,
constants folded through OCaml floats, and the libc contracts under each analysis. A second pass
then tried to refute each finding. I have filed none of it, and will not until you say how you
would like it (question 2). Everything below has a reproducer of a few lines that was run on
`master` (`b80fcac74f`) and on `34.0~beta`, and I found none of it on the tracker.

*Edit, 18 November: added the contract of `strlcat` (Libc, reference 44 in the annex).*

*Edit, 18 November: added a request about the MetAcsl plug-in (reference 45, at the end of the
annex). It would go to `pub/meta`, and it is not filed either.*

*Edit, 20 November: added guarded `\old`/`\at` evaluation (E-ACSL), `<sched.h>` `cpu_set_t`
(Libc, reference 46), and three MetAcsl reports for `pub/meta` (references 47 to 49, including a
wrong proof in 47; patches ready, and 45's patch is now built too).*

*Edit, 22 November: added `--validate-format-strings` crashing on `enum` arguments and `enum *`
pointers in `printf`-family calls (E-ACSL, reference 50 in the annex; validated on `master`
`189053d4a2` and `34.0~beta`, patch ready).*

*Edit, 23 November: re-validated `46` (`<sched.h>`) and the remaining hunt findings on `master`
`189053d4a2` and `34.0~beta` (patches ready for `46` and every kept hunt finding except `N1`,
which stays a design question; `H9`, `L6`, and `N21` dropped/deferred), and corrected factual
details in annex rows `N18`, `L4`, `H15`, `N6`, `N12`, `N5`, `N11`, `H12`, and `N20`.*

One of them is a question before it is a report, because the behaviour is deliberate.

**Enumeration constants.** Since the change "Fix enumeration typing by making sure all items are
of type ekind" (Changelog, 2026-04-10), an enumeration constant has the type of its enum, which
is `unsigned int` for an enum without a negative member:

```c
enum { N = 4 };
int a[N];
int get(int i)
{
  if (i < N)
    return a[i];
  return -1;
}
```

`frama-c -print` shows `if ((unsigned int)i < N)`. With gcc the constant has type `int` (C11
6.7.2.2p3), so `get(-1)` reads `a[-1]`. `frama-c -wp -wp-rte` proves `get` (4 goals out of 4),
and the program that E-ACSL instruments takes the other branch, since the printed code carries
the unsigned comparison. `-enums int` changes the constants and also makes objects of the enum
type signed, so no option gives gcc's typing. Is the new typing intended? The Changelog entry
refers to an issue I cannot read.

The others, by component. I listed only those where an analysis gives a wrong answer:

| Component | What happens |
| :-- | :-- |
| Libc | `pclose`: the `requires` and the `ensures` contradict each other, so WP proves `\false` after a call. |
| Libc | `strlcat`: the `ensures` states the result against `strlen(dest)` after the call, and the `assigns` includes `dest[n]`. For `char f[8] = "abcdef";`, `strlcat(f, "x", 3)` returns 4 and Eva gives `{7}` without an alarm; WP proves `\result == strlen(d) + strlen(s)` after the call for a caller where the result is 4 and the sum is 6. I have a patch for this one. |
| Libc | `sigaction` with a non-null `oldact`: Eva reports "this postcondition evaluates to false" and the code after the call is dead. `getpwnam_r`, `getpwuid_r` (and `getut*_r` in `utmp.h`): the success branch is dead for Eva. |
| Libc | `syslog` in a file that includes only `<syslog.h>`: the string preconditions are not generated, and an unterminated `%s` argument raises no alarm. |
| WP | After the warning `void object`, a `void` object is sized as an `int`: for `char buf[8]; void *p = buf;`, `\block_length(p) == 32` is proved. Under `-wp-model Bytes`, `(char *)(p + 4) == buf + 16` is proved. |
| WP | `\floor`, `\ceil`, `\truncate` and float-to-integer casts of a constant go through an OCaml `float` and `int`: `\floor(0.99999999999999999999) == 1` is proved, and so is a false post-condition on `(long long)d` with `d = 5e18`. |
| WP | The sum of two ranges, and `p + (a..b) + (c..d)`, ignore an empty range: an `assigns` over an empty set accepts a write. |
| Kernel | In a term, `(float)` of a literal that is exact as a `double` and not as a `float` is dropped: `(float)16777217.0 == 16777217.0` is valid for Eva and proved by WP. |
| Kernel | ACSL literals are not read as C reads them: `L'\x20AC'` in an annotation is not the C constant, and `sizeof("hello\n")` is 8. |
| Kernel | A `double` constant without source text is printed with 12 significant digits (after `-constfold`, which `e-acsl-gcc` passes by default, or `-scf`), so the printed program computes other values; `1.0 / 0.0` is printed `inf`. |
| E-ACSL | `(double)` of a real is truncated, not rounded: with `double e = 0.1;`, `e == (double)0.1` fails, and it passes for the `double` just below 0.1. |
| E-ACSL | A real constant with an exponent (`1e-9`) stops Frama-C with `Not_a_decimal`, and `0.1L` is 0 at run time. I have a patch for this one. |

Beside these I have about thirty smaller ones: wrong values from contrived input, internal
errors on unusual input (option values, annotation syntax, `stpncpy` and `strlcat` under
E-ACSL), and corner cases of wide literals in the lexer and the printer. The annex at the end
of this text lists every finding, the ones above included, in one line each.

### Questions

1. **Is the bittree memory model still supported?** With it, every `free` aborts (#2826). If the
   model is on its way out, I will close #2826, #2827, !54 and !55.
2. **How would you like further findings?** An issue alone, or an issue with a merge request? One
   at a time, or grouped by component as in the table above? Which of them do you want at all? I
   have stopped filing, and nothing from that table will be filed until you answer.
3. **Would fewer merge requests help?** I can combine the ones that go together (!48, !49 and !50
   for the format checks; !40 and !41 for `e-acsl-gcc`; !54 and !55 for bittree), and mark the
   low-priority ones as drafts so that they leave your review queue.

**Contributor Licence Agreement:** I have not signed it yet, which is why that box is unticked on
every merge request. I will send it before you spend review time on anything beyond a trivial
patch.

Two issues already ask you to choose between possible fixes (#2815 and #2816). There is no hurry
on either.

Thank you for the triage so far, and for opening the fork settings.

### Annex: every finding that is not filed

One line each, so that you can say which ones you want. The references are my own labels (the
gaps are findings I dropped). Each has a reproducer of a few lines, validated on `master`
(`189053d4a2`, initially `b80fcac74f`) and on `34.0~beta`, except `N21` ("`master` only") and the
four MetAcsl reports (45, 47 to 49), which were run on Frama-C `34.0~beta` (MetAcsl `0.12~beta`
and `pub/meta` `4f43801390`). Every non-dropped row except `N1` and `old-guard` now has a
validated patch ready (`H10`+`N4`, `H6`+`H18`, `H3`+`N2`, and `H12`+`N14` are paired).

**Kernel, C front end**

| Ref | What happens | Kind |
| :-- | :-- | :-- |
| N1 | An enumeration constant has the unsigned type of its enum, not `int` (see the question above). | wrong proof, wrong status, the printed program differs |
| H5 | A character constant of 0x80 or more is negative whatever the machdep says about `char`: with `-machdep ppc_32`, `'\377' == 255` is false, and so is `a[0] == '\377'` for `char a[] = "\377"`. | wrong status |
| H8 | A multi-character constant is `unsigned long` (`unsigned long long` with four characters), not `int`: `('ab' - 30000) < 0` is 0 and `sizeof('ab')` is 8. | wrong status |
| N7 | A hexadecimal floating-point literal with an `f` suffix is rounded twice: `0x1.0000010000000001p0f` is read as `0x1p0` (gcc: `0x1.000002p+0`). | wrong value, contrived |
| N13 | A universal character name in a literal is rejected ("Unrecognized escape sequence"). | valid C99 rejected |
| N18 | `int c = '\777';` (and `'\x1ff'`) is accepted without a message, as 511 (gcc warns; C11 6.4.4.4p9 is a constraint). Reproduces on both `master` and `34.0~beta`. | minor |
| H9 | UTF-8 bytes in a wide literal give one `wchar_t` per byte (`L'€'` is 172), silently. Implementation-defined (dropped as not a bug). | documentation (dropped) |

**Kernel, ACSL front end**

| Ref | What happens | Kind |
| :-- | :-- | :-- |
| H4 | `(float)` of a literal that is exact as a `double` and not as a `float` is dropped: `(float)16777217.0 == 16777217.0` is valid for Eva and proved by WP; true properties get status invalid. | wrong proof, wrong status |
| N8 | `(_Bool)` of a literal from 0 to 255 is dropped: `(_Bool)2 == 2` is valid. | wrong status, contrived |
| H6 | A hexadecimal escape in a character constant or a narrow string is cut into pairs of digits, and a wide constant is not truncated: `L'\x20AC'` is 0x20000000AC, so a correct program aborts under E-ACSL on `w == L'\x20AC'`. | wrong proof, wrong status, wrong run-time check |
| H7 | A string literal is typed from its text before the escapes are read: `sizeof("\n") == 3` is proved, and `sizeof` of a macro such as `"hello\n"` is off by one in a contract. | wrong proof, wrong status |
| N9 | Adjacent string literals are concatenated before the escapes are read: `"\x4" "1"` is `"A"`. | wrong value, contrived |
| N10 | An escape that the logic lexer does not list (`'\e'`) is kept as a backslash and a character, without a message. | wrong value, contrived |
| N11 | In a wide string, `8` and `9` count as octal digits (`L"\18"[0]` is 16) and `\v` is missing. | wrong value, contrived |
| H18 | `'\777'`, or `L'\777'` (valid C), in an annotation: `Invalid_argument("Char.chr")`. | internal error |
| N19 | An unbalanced quote in an annotation (or a C23 digit separator): a user error, then "too few annotations in result file while preprocessing annotations". | internal error |
| N21 | `//@ check 10uu == 10;` aborts Frama-C even with `-kernel-warn-key annot-error=active`. `master` only (deferred). | minor (deferred) |

**Kernel, printer**

| Ref | What happens | Kind |
| :-- | :-- | :-- |
| H10 | A `double` constant without source text is printed with 12 significant digits (after `-constfold`, which `e-acsl-gcc` passes by default, after `-scf`, and for constants that E-ACSL builds): `1.0 / 3.0` becomes `0.333333333333`. | the printed program computes other values; wrong run-time check |
| N4 | A non-finite constant is printed `inf`, `-inf` or `nan`: `double a = 1.0 / 0.0;` does not compile after `-constfold`, so default `e-acsl-gcc` fails on it. | the printed program does not compile |
| N5 | An `__int128` constant is printed with the suffix `LL`; gcc truncates it with a warning, clang fails to compile, and Frama-C rejects its own output on re-parse (`Cannot represent the integer`). | the printed program computes other values / fails re-parse |
| H12 | A wide character of 0x200 or more is printed as a universal character name in the four-digit form, with more digits when the value needs them: above 0xFFFF a compiler reads another value, surrogates (`\xD800`) fail gcc, values `>= 2^32` crash (`Invalid_argument("Cprint.escape_string_intlist")`), and Frama-C cannot read any of them back (N13). | the printed program differs / internal error |
| N12 | A wide string in an annotation is escaped twice, so the printed file means something else, and empty `L""` prints as invalid `L` (`unbound logic variable L`). | the printed annotation differs / fails re-parse |
| N14 | Trigraphs are not protected in a wide string: `L"a?\?!b"` is printed `L"a??!b"`, and `e-acsl-gcc` compiles with `-std=c99`. | the printed program differs, contrived |

**WP**

| Ref | What happens | Kind |
| :-- | :-- | :-- |
| L1 | After the warning `void object`, a `void` object is sized as an `int`: `\block_length(p) == 32` is proved for `char buf[8]; void *p = buf;`, and under `-wp-model Bytes` `(char *)(p + 4) == buf + 16` is proved. | wrong proof |
| H1 | `\floor`, `\ceil`, `\truncate` and float-to-integer casts of a constant go through an OCaml `float` and `int`: `\floor(0.99999999999999999999) == 1` is proved, and so is a false post-condition on `(long long)d` with `d = 5e18`. | wrong proof |
| H2 | A constant rounded to `float` goes through `double` first: for `long long x = 1152921573326323713LL;`, `(float)x == 1152921504606846976.0` is proved (gcc gives the other neighbour). | wrong proof, contrived |
| H3, N2 | The sum of two ranges ignores an empty range: `8 \in ((5..3) + (0..10))` is proved, and `assigns *(p + (0 .. n-1) + (0 .. 1));` with `n == 0` accepts a write to `*p`. | wrong proof |
| N3 | A constant that overflows its format becomes an infinite "real": with `double x = 1e308; double y = x * 10.0; double z = x * 20.0;`, `y + 1.0 == z` is proved by Qed, and the goals that hold such a constant fail in the prover with `Invalid_argument("Wp.Cfloat.const_float")`. | wrong proof behind an overflow, prover failure |
| H16 | `strategy S: \prover("Alt-Ergo", 2u);` (or a timeout of `99999999999999999999`): `Failure("int_of_string")`. | internal error |
| H17 | `-wp-time-margin 1s`: `Failure("float_of_string")` after the provers ran; the manual says "Default is 5s". | unexpected error |
| N16 | `-wp-par 0`: `Invalid_argument("Prove_client.set_max_running_provers")`. | unexpected error |

**Eva**

| Ref | What happens | Kind |
| :-- | :-- | :-- |
| H14 | The `numerors` domain reads a literal's text with a decimal-only parser: `0x1.8p1` is 0.048, `DBL_MAX` gets another value (a sure out-of-bounds alarm is lost on an example), and `FLT_MAX`, `INFINITY` and `NAN` end in an unexpected error. | lost alarm and errors, in an experimental domain |
| N15 | `//@ loop unroll 1/0;`: `Unexpected error (Division_by_zero)`. | unexpected error |

**E-ACSL**

| Ref | What happens | Kind |
| :-- | :-- | :-- |
| 43 | A real constant with an exponent (`1e-9`) stops Frama-C with `Not_a_decimal`, and `0.1L` is 0 at run time. Patch ready. | unexpected error, wrong run-time check |
| 50 | `--validate-format-strings`: any `enum` argument to a `printf`-family function crashes Frama-C with `Assertion failed` in `plugins/e-acsl/src/libraries/functions.ml:156` (`get_printf_argument_str`), and a pointer to an `enum` (such as `&s` for `%n`) aborts with `unexpected argument type in printf`. Patch ready (stacks cleanly with !48). | internal error |
| H11 | `(double)` of a real is truncated (`mpq_get_d`), not rounded: with `double e = 0.1;`, `e == (double)0.1` fails, and it passes for the `double` just below 0.1. | wrong run-time check, both ways |
| H15 | `x < 1e40f` in an annotation gives `x < inf` in the generated code, and `0.1 < 1e40f` passes infinity to `__gmpq_set_d` (`SIGFPE` at run time, independent of N4). | the generated code does not compile / runtime crash |
| old-guard | An `\old` or `\at` term is evaluated at its label even when a guard (`\old(p) == \null ==> ...`, disjunction, or `assumes`) makes it unneeded (`Translate_ats.for_stmt`): valid calls abort at run time with default options, including Frama-C's libc `recvfrom(..., NULL, NULL)` under `e-acsl-gcc -L`. | false alarm on valid code |
| L4 | `typing was not performed on construct 1` on a call to `stpncpy` or `strlcat`, and on a quantifier bounded by a logic function without a definition. Confirmed distinct from #2806 (still aborts on top of !37). For `strlcat` it comes from the `ensures` clause of 44 (Libc): with that clause rewritten, the translation ends normally. | internal error |
| L6 | A call to `getaddrinfo` prints lines `Failure: Interval inference was not performed on construct \result`, with exit code 0 (dropped as cosmetic). | cosmetic (dropped) |

**Libc**

| Ref | What happens | Kind |
| :-- | :-- | :-- |
| L2 | `pclose`: the `requires` and the `ensures` contradict each other, so WP proves `\false` after a call. | wrong proof |
| 44 | `strlcat`: `ensures bounded_result: \result == strlen(dest) + strlen(src);` reads `strlen(dest)` after the call, and `assigns dest[strlen(dest)..n]` includes `dest[n]`. Eva gives `{7}` for a call that returns 4, without an alarm, and considers a structure field that follows the buffer modified; WP proves a false postcondition for a caller. Also, `requires separation` covers only `src+(0..strnlen(src, n-1))`, while the function reads `src` up to its NUL: `strlcat(buf + 16, buf, 8)` on `char buf[32] = "0123456789abcdefghij";` writes over the NUL of `src` with every precondition valid. Patch ready. | wrong value for Eva, wrong proof, lost alarm |
| L3 | `sigaction` with a non-null `oldact`: Eva reports "this postcondition evaluates to false" and the code after the call is dead. | lost code for Eva |
| N6 | `getpwnam_r`, `getpwuid_r` (`pwd.h`), and `getutent_r`, `getutid_r`, `getutline_r` (`utmp.h`): Eva gives `NULL` as the only result, so the success branch is dead. | lost code for Eva |
| L5 | `syslog` in a file that includes only `<syslog.h>`: "Unable to locate ACSL predicate valid_read_string", and an unterminated `%s` argument raises no alarm. | lost alarm |
| N20 | `wprintf`/`wscanf` in a file that includes only `<wchar.h>`: "Unable to locate global `__fc_stdout`/`__fc_stdin`"; the effect on the stream is missing. | minor |
| 46 | `<sched.h>` lacks glibc's `cpu_set_t`, `CPU_*` macros and `sched_setaffinity`/`sched_getaffinity` under `_GNU_SOURCE`. Patch ready. | header gap |

**Other**

| Ref | What happens | Kind |
| :-- | :-- | :-- |
| N17 | A custom machdep with `sizeof_int: 0`: `Invalid_argument("Z.shift_left: count argument must be positive")`. | unexpected error |

**MetAcsl** (for `pub/meta`)

| Ref | What happens | Kind |
| :-- | :-- | :-- |
| 45 | `\result` is refused in a `\postcond` property (`\result meaningless`), although the property becomes an `ensures` clause of its target, so "when the function fails, the state is unchanged" cannot be a meta-property. Patch ready. | feature request |
| 47 | At a call to a callee known by its contract, `\written`/`\read` instances copy the callee's `Old`, `Pre` and `Here` labels unchanged: `Old` aborts WP and E-ACSL, while `Pre` and `Here` (under `After`) refer to the wrong state so WP proves false properties. Patch ready. | wrong proof, internal error |
| 48 | Under `-meta-fold`, `create_call` (and the `post`/`post_fold` wrappers) drops `~loc`, so folded instances have no source location (`<unknown>:0` at run time under E-ACSL). Patch ready. | missing locations |
| 49 | A call to a function without any specification (such as host libc under `e-acsl-gcc`) gets no `\writing`/`\reading` instance and no warning (patch ready for a `no-footprint` warning); `\written`/`\read`/`\called` terms also omit `~loc` (`<unknown>:0` in E-ACSL validity guards). | feature request |
