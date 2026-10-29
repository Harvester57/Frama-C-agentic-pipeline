# E-ACSL Quick Reference (Frama-C 33.0)

Distilled by hand from the E-ACSL plug-in manual [`eacsl/e-acsl-manual.md`](eacsl/e-acsl-manual.md); `§` numbers refer to that manual. Grep its section for details (see [`README.md`](README.md)). For which ACSL constructs E-ACSL can execute at all, see Figure 1.1 of [`acsl/e-acsl-implementation.md`](acsl/e-acsl-implementation.md).

The installed tool is the authority on option names: `e-acsl-gcc -h` or `man e-acsl-gcc` in the container (§2.2.6). The manual is not fully consistent. §2.2 documents the Frama-C 33 `e-acsl-gcc` short options, while some examples in §2.4 and §2.5.4 still use older spellings (`-c`, `--oexec-e-acsl`, `--e-acsl-extra`).

## `e-acsl-gcc` wrapper

Frama-C 33 installs it as `e-acsl-gcc`, not `e-acsl-gcc.sh`. By default it uses `-machdep gcc_x86_64` and `-m64`; ABIs other than the default are not supported (§2.2.4).

| Option | Effect | § |
| :--- | :--- | :--- |
| *(no mode option)* | Instrument, then compile **and link** two executables: the original program (`a.out`, or the `-O` name) and the instrumented one (same name + `.e-acsl`) | 2.2.1 |
| `-n` | Instrument only: no compile, no link | 2.2.1 |
| `-o <file>` | Output file for the instrumented source (default `a.out.frama.c`) | 2.2.1 |
| `-O <name>` | Executable name; the instrumented executable is `<name>.e-acsl` | 2.2.1 |
| `-C` | Inputs are already instrumented: compile and link them into `<name>.e-acsl` only | 2.2.1 |
| `-I <path>` / `-G <path>` | `frama-c` / compiler executable to use | 2.2.2 |
| `-F "<flags>"` | Extra Frama-C flags | 2.2.2 |
| `-E "<args>"` | Extra arguments for Frama-C's preprocessor | 2.2.2 |
| `-e "<flags>"` / `-l "<flags>"` | Extra compiler preprocessor / linker flags | 2.2.2 |
| `-v <n>` / `-d <n>` / `-q` / `-s <file>` | Frama-C `-verbose` / `-debug`; quiet; redirect all output to a file | 2.2.3 |
| `-L` | Use Frama-C's libc and its contracts (off by default in the wrapper) | 2.3.2 |
| `-g` | GMP arithmetic for every integer (`-e-acsl-gmp-only`); can be much slower | 2.3.3 |
| `-m segment\|bittree` | Memory model. `segment` (shadow memory) is the default: more than 2x memory, often 10x faster. `-msegment,bittree` builds both | 2.3.4 |
| `-M` | Full memory tracking (`-e-acsl-full-mtracking`) | 2.3.4 |
| `--rte=<kinds>` | Run RTE first and check its assertions at runtime (`all` or a comma list; see the man page) | 2.6 |
| `--fail-with-code=<n>` | On a violation, `exit(n)` instead of `abort()` | 2.3.5 |
| `--keep-going` | Report every violation and keep running; may give incorrect verdicts | 2.3.5 |
| `--no-assert-print-data` | Don't print the values involved in a failing predicate (printed by default) | 2.3.5 |
| `--external-assert=<file.c>` / `--external-print-value=<file.c>` | Custom `__e_acsl_assert` / `__e_acsl_print_value` | 2.3.5 |
| `--validate-format-strings` | Check `printf`-like format strings against argument types | 2.4.1 |
| `--libc-replacements` | Check `memcpy`, `memmove`, `memset`, `memcmp`, `str[n]cpy`, `str[n]cat`, `str[n]cmp`, `strlen` usage (`-e-acsl-replace-libc-functions`) | 2.4.2 |
| `--concurrency` | pthreads support: `-e-acsl-concurrency`, `-DE_ACSL_CONCURRENCY_PTHREAD`, `-pthread` | 2.2.5 |

## Frama-C `-e-acsl-*` options

| Option | Effect | § |
| :--- | :--- | :--- |
| `-e-acsl` | Translate annotations into a new project named `e-acsl`. Print it with `-then-last -print -ocode out.c` | 2.1 |
| `-e-acsl-functions f,g` | Check only the annotations of these functions; the others get no runtime check. Unlike `-e-acsl-instrument`, instrumentation is not reduced | 2.5.3 |
| `-e-acsl-instrument=+@all,-f` | Experimental: skip instrumenting some functions. All annotations are still checked, but verdicts can become unsound | 2.5.4 |
| `-e-acsl-full-mtracking` | Same as `-M` | 2.3.4 |
| `-e-acsl-gmp-only` | Same as `-g` | 2.3.3 |
| `-e-acsl-valid` | Also check annotations another plug-in already proved valid in the same session (skipped otherwise) | 2.6 |
| `-e-acsl-builtins=f,g` | Allow these side-effect-free C functions in annotations | 2.3.6 |
| `-e-acsl-replace-libc-functions` | Same as `--libc-replacements` | 2.4.2 |
| `-e-acsl-concurrency` | Generate concurrency-ready code | 2.2.5 |
| `-e-acsl-widening-arguments f:3,…`, `-e-acsl-widening-output f:1,…` (+ `-base <n>`) | Integer typing widening for recursive functions (experts only) | 2.3.3 |
| `-e-acsl-project <name>` | Name of the generated project | 2.7 |
| `-e-acsl-verbose <0-4>`, `-e-acsl-msg-key analysis\|preparation\|translation\|typing` | Verbosity level and message categories | 2.8 |

## Runtime output

- **Violation** (§2.2.1, §2.3.5): the monitor prints the report below and calls `abort()` (shell exit status 134), unless `--fail-with-code` or `--keep-going` is set. Contract failures use the clause kind, for example `Postcondition failed:` (§2.5.2).
  ```text
  first.i: In function 'main'
  first.i:4: Error: Assertion failed:
          The failing predicate is:
          x == 1.
          With values:
          - x: 0
  ```
- **Runtime error inside an annotation** (§2.3.1): E-ACSL logic is partial, so an undefined term is reported instead of evaluated, for example `RTE failed at line 5 in function is_dividable.` followed by `The failing predicate is: division_by_zero: y != 0.`
- **Untrustworthy verdict** (§2.3.5, §2.5.4): `Warning: no sound verdict for Assertion (guess: ok|FAIL).` Execution **continues**, and the guess can be wrong. A custom `__e_acsl_assert` can read `__e_acsl_sound_verdict`.
- **Memory tracking** (§2.3.4): the runtime replaces `malloc`, `calloc`, `free` and friends with its own dlmalloc, and records block bounds, per-byte initialization and freeability.

## Limitations that change verdicts

- **Constructs not executed:** `assigns`, `loop assigns`, `decreases`, lemmas, axiomatic definitions, `\dangling`, … (Figure 1.1 of `acsl/e-acsl-implementation.md`). Only WP validates them.
- **Memory analysis robustness:** the static analysis that trims memory instrumentation is "probably the less robust part of E-ACSL". On large code, turn it off with `-M` (§2.3.4).
- **No `main`** (for example, a libFuzzer harness): instrumentation of memory-related annotations (`\valid`, `\initialized`, RTE `mem_access`) is partial and violations go undetected, unless `-M` / `-e-acsl-full-mtracking` is used. A `main` provided by another file must first call `__e_acsl_memory_init` and `__e_acsl_globals_init` (§3.3.1).
- **Undefined functions, recursion, function pointers, incomplete types:** violations of memory-related annotations that depend on them go undetected, with no workaround (§3.3.2, §3.3.3, §3.4, §3.6). Undefined variadic functions with contracts are not supported (§3.5).
- **Uninitialized values** read inside an annotation are not detected; write `\initialized(...)` explicitly (§3.2).
- **Concurrency:** a function contract is evaluated outside the locks taken in the body, so its verdict depends on thread interleaving. Use a statement contract inside the lock instead (§2.2.5).
- **Platform:** only 64-bit Linux is well supported. The segment model assumes little-endian, and the runtime library is not thread-safe (§3.1).
- **Input programs** must not define `__e_acsl_*` symbols, `syscall`, `mmap` or `sbrk`, or redefine the `malloc` family. Non-standard allocators (`valloc`, `memalign`, `pvalloc`) may not be monitored correctly (§3.7).
- **Prior proofs:** annotations proved by another plug-in earlier in the same Frama-C session are not checked unless `-e-acsl-valid` is set (§2.6).
