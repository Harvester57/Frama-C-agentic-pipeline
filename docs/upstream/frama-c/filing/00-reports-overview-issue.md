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

| Report | Fix | Why |
| :-- | :-- | :-- |
| #2793 | !25 | E-ACSL lets a false predicate pass at run time, with default options and an ordinary guarded quantifier. No warning. |
| #2800 | !31 | `<==>` over `\old`, `\at` or a formal in a postcondition aborts the instrumentation. A 34.0 development build translated it; `34.0~beta` and `master` do not. |
| #2797 | !28 | Closed issue #177 fails again: formal parameters are never marked initialized. |
| #2831 | !59 | WP does not read hexadecimal floating-point literals: a hypothesis on `DBL_MAX` is dropped, and under `-wp-model +real` a suffixed literal is read as 0 (a wrong proof). |
| #2798, #2799 | !29, !30 | An unbounded range aborts the whole E-ACSL instrumentation, and Frama-C's libc contracts contain some (`getsockopt`, `strtok_r`, four `wcs*` functions). |

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

**E-ACSL (27)**

- Wrong verdict: #2793
- The instrumentation aborts, or its output does not compile: #2795, #2798, #2800, #2804, #2805,
  #2806, #2816
- A correct program fails at run time: #2794, #2797, #2801, #2802, #2803, #2815, #2817, #2818
- `--validate-format-strings`: #2819, #2820, #2821, #2822
- bittree memory model: #2826, #2827
- `e-acsl-gcc` and options: #2807, #2808, #2809, #2810, #2825

**Kernel (4):** #2796, #2812, #2813, #2824

**Libc (5):** #2799, #2814, #2823, #2828, #2830

**WP (3):** #2811, #2829, #2831

### Findings I have not filed

After #2831 I looked for the same kinds of mistake elsewhere: a literal read by a second parser,
constants folded through OCaml floats, and the libc contracts under each analysis. A second pass
then tried to refute each finding. I have filed none of it, and will not until you say how you
would like it (question 2). Everything below has a reproducer of a few lines that was run on
`master` (`b80fcac74f`) and on `34.0~beta`, and I found none of it on the tracker.

*Edit, 18 November: added the contract of `strlcat` (Libc, reference 44 in the annex).*

*Edit, 18 November: added a request about the MetAcsl plug-in (reference 45, at the end of the
annex). It would go to `pub/meta`, and it is not filed either.*

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
| Libc | `sigaction` with a non-null `oldact`: Eva reports "this postcondition evaluates to false" and the code after the call is dead. `getpwnam_r`, `getpwuid_r`: the success branch is dead for Eva. |
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
gaps are findings I dropped). Each has a reproducer of a few lines, run on `master`
(`b80fcac74f`) and on `34.0~beta`, except the two marked "`master` only" and reference 45 (MetAcsl),
which was run on `34.0~beta` only.

**Kernel, C front end**

| Ref | What happens | Kind |
| :-- | :-- | :-- |
| N1 | An enumeration constant has the unsigned type of its enum, not `int` (see the question above). | wrong proof, wrong status, the printed program differs |
| H5 | A character constant of 0x80 or more is negative whatever the machdep says about `char`: with `-machdep ppc_32`, `'\377' == 255` is false, and so is `a[0] == '\377'` for `char a[] = "\377"`. | wrong status |
| H8 | A multi-character constant is `unsigned long` (`unsigned long long` with four characters), not `int`: `('ab' - 30000) < 0` is 0 and `sizeof('ab')` is 8. | wrong status |
| N7 | A hexadecimal floating-point literal with an `f` suffix is rounded twice: `0x1.0000010000000001p0f` is read as `0x1p0` (gcc: `0x1.000002p+0`). | wrong value, contrived |
| N13 | A universal character name in a literal is rejected ("Unrecognized escape sequence"). | valid C99 rejected |
| N18 | `int c = '\777';` is accepted without a message, as 511 (gcc warns; C11 6.4.4.4p9 is a constraint). `master` only. | minor |
| H9 | UTF-8 bytes in a wide literal give one `wchar_t` per byte (`L'€'` is 172), silently. Implementation-defined, so only a request for a warning or a sentence in the manual. | documentation |

**Kernel, ACSL front end**

| Ref | What happens | Kind |
| :-- | :-- | :-- |
| H4 | `(float)` of a literal that is exact as a `double` and not as a `float` is dropped: `(float)16777217.0 == 16777217.0` is valid for Eva and proved by WP; true properties get status invalid. | wrong proof, wrong status |
| N8 | `(_Bool)` of a literal from 0 to 255 is dropped: `(_Bool)2 == 2` is valid. | wrong status, contrived |
| H6 | A hexadecimal escape in a character constant or a narrow string is cut into pairs of digits, and a wide constant is not truncated: `L'\x20AC'` is 0x20000000AC, so a correct program aborts under E-ACSL on `w == L'\x20AC'`. | wrong proof, wrong status, wrong run-time check |
| H7 | A string literal is typed from its text before the escapes are read: `sizeof("\n") == 3` is proved, and `sizeof` of a macro such as `"hello\n"` is off by one in a contract. | wrong proof, wrong status |
| N9 | Adjacent string literals are concatenated before the escapes are read: `"\x4" "1"` is `"A"`. | wrong value, contrived |
| N10 | An escape that the logic lexer does not list (`'\e'`) is kept as a backslash and a character, without a message. | wrong value, contrived |
| N11 | In a wide string, `8` and `9` count as octal digits: `L"\18"[0]` is 16. | wrong value, contrived |
| H18 | `'\777'`, or `L'\777'` (valid C), in an annotation: `Invalid_argument("Char.chr")`. | internal error |
| N19 | An unbalanced quote in an annotation (or a C23 digit separator): a user error, then "too few annotations in result file while preprocessing annotations". | internal error |
| N21 | `//@ check 10uu == 10;` aborts Frama-C even with `-kernel-warn-key annot-error=active`. `master` only. | minor |

**Kernel, printer**

| Ref | What happens | Kind |
| :-- | :-- | :-- |
| H10 | A `double` constant without source text is printed with 12 significant digits (after `-constfold`, which `e-acsl-gcc` passes by default, after `-scf`, and for constants that E-ACSL builds): `1.0 / 3.0` becomes `0.333333333333`. | the printed program computes other values; wrong run-time check |
| N4 | A non-finite constant is printed `inf`, `-inf` or `nan`: `double a = 1.0 / 0.0;` does not compile after `-constfold`, so default `e-acsl-gcc` fails on it. | the printed program does not compile |
| N5 | An `__int128` constant is printed with the suffix `LL`; gcc truncates it with a warning only. | the printed program computes other values |
| H12 | A wide character of 0x200 or more is printed as a universal character name in the four-digit form, with more digits when the value needs them: above 0xFFFF a compiler reads another value, and Frama-C cannot read any of them back (N13). | the printed program differs |
| N12 | A wide string in an annotation is escaped twice, so the printed file means something else. | the printed annotation differs |
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
| H11 | `(double)` of a real is truncated (`mpq_get_d`), not rounded: with `double e = 0.1;`, `e == (double)0.1` fails, and it passes for the `double` just below 0.1. | wrong run-time check, both ways |
| H15 | `x < 1e40f` in an annotation gives `x < inf` in the generated code. | the generated code does not compile |
| L4 | `typing was not performed on construct 1` on a call to `stpncpy` or `strlcat`, and on a quantifier bounded by a logic function without a definition. Possibly related to #2806. For `strlcat` it comes from the `ensures` clause of 44 (Libc): with that clause rewritten, the translation ends normally. | internal error |
| L6 | A call to `getaddrinfo` prints lines `Failure: Interval inference was not performed on construct \result`, with exit code 0. | cosmetic |

**Libc**

| Ref | What happens | Kind |
| :-- | :-- | :-- |
| L2 | `pclose`: the `requires` and the `ensures` contradict each other, so WP proves `\false` after a call. | wrong proof |
| 44 | `strlcat`: `ensures bounded_result: \result == strlen(dest) + strlen(src);` reads `strlen(dest)` after the call, and `assigns dest[strlen(dest)..n]` includes `dest[n]`. Eva gives `{7}` for a call that returns 4, without an alarm, and considers a structure field that follows the buffer modified; WP proves a false postcondition for a caller. Also, `requires separation` covers only `src+(0..strnlen(src, n-1))`, while the function reads `src` up to its NUL: `strlcat(buf + 16, buf, 8)` on `char buf[32] = "0123456789abcdefghij";` writes over the NUL of `src` with every precondition valid. Patch ready. | wrong value for Eva, wrong proof, lost alarm |
| L3 | `sigaction` with a non-null `oldact`: Eva reports "this postcondition evaluates to false" and the code after the call is dead. | lost code for Eva |
| N6 | `getpwnam_r`, `getpwuid_r`: Eva gives `NULL` as the only result, so the success branch is dead. | lost code for Eva |
| L5 | `syslog` in a file that includes only `<syslog.h>`: "Unable to locate ACSL predicate valid_read_string", and an unterminated `%s` argument raises no alarm. | lost alarm |
| N20 | `wprintf` in a file that includes only `<wchar.h>`: "Unable to locate global __fc_stdout"; the effect on the stream is missing. | minor |

**Other**

| Ref | What happens | Kind |
| :-- | :-- | :-- |
| N17 | A custom machdep with `sizeof_int: 0`: `Invalid_argument("Z.shift_left: count argument must be positive")`. | unexpected error |

**MetAcsl** (for `pub/meta`)

| Ref | What happens | Kind |
| :-- | :-- | :-- |
| 45 | `\result` is refused in a `\postcond` property (`\result meaningless`), although the property becomes an `ensures` clause of its target, so "when the function fails, the state is unchanged" cannot be a meta-property. Run on `34.0~beta` with MetAcsl `0.12~beta` only; `meta_parse.ml` is the same file on MetAcsl `master`. I have a patch that I have not built. | feature request |
