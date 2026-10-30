# E-ACSL Quick Reference (Frama-C 33.0)

Distilled by hand from the E-ACSL plug-in manual [`eacsl/e-acsl-manual.md`](eacsl/e-acsl-manual.md); `§` numbers refer to that manual. Grep its section for details (see [`README.md`](README.md)). For which ACSL constructs E-ACSL can execute at all, see Figure 1.1 of [`acsl/e-acsl-implementation.md`](acsl/e-acsl-implementation.md).

The installed tool is the authority on option names: `e-acsl-gcc -h` or `man e-acsl-gcc` in the container (§2.2.6). The manual is not fully consistent. §2.2 documents the Frama-C 33 `e-acsl-gcc` short options, while some examples in §2.4 and §2.5.4 still use older spellings (`-c`, `--oexec-e-acsl`, `--e-acsl-extra`).

## `e-acsl-gcc` wrapper

Frama-C 33 installs it as `e-acsl-gcc`, not `e-acsl-gcc.sh`. By default it uses `-machdep gcc_x86_64` and `-m64`; ABIs other than the default are not supported (§2.2.4). In the container, `e-acsl-gcc -h` lists only the basic short options, but long options such as `--rte=all` are still accepted (see "Verified in the pipeline container" below).

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
| `--rte=<kinds>` | Run RTE first and check its assertions at runtime (`all` or a comma list; see the man page). `--rte=all` also adds `-warn-unsigned-overflow`, `-warn-signed-downcast` and `-warn-unsigned-downcast`, which a plain `-F -rte` does not | 2.6 |
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
- **No `main`** (for example, a libFuzzer harness): according to the manual, instrumentation of memory-related annotations (`\valid`, `\initialized`, RTE `mem_access`) is partial and violations go undetected, unless `-M` / `-e-acsl-full-mtracking` is used. A `main` provided by another file must first call `__e_acsl_memory_init` and `__e_acsl_globals_init` (§3.3.1). In the container, the observed failure is a false alarm on valid stack accesses rather than a missed violation; see below.
- **Undefined functions, recursion, function pointers, incomplete types:** violations of memory-related annotations that depend on them go undetected, with no workaround (§3.3.2, §3.3.3, §3.4, §3.6). Undefined variadic functions with contracts are not supported (§3.5).
- **Uninitialized values** read inside an annotation are not detected; write `\initialized(...)` explicitly (§3.2).
- **Concurrency:** a function contract is evaluated outside the locks taken in the body, so its verdict depends on thread interleaving. Use a statement contract inside the lock instead (§2.2.5).
- **Platform:** only 64-bit Linux is well supported. The segment model assumes little-endian, and the runtime library is not thread-safe (§3.1).
- **Input programs** must not define `__e_acsl_*` symbols, `syscall`, `mmap` or `sbrk`, or redefine the `malloc` family. Non-standard allocators (`valloc`, `memalign`, `pvalloc`) may not be monitored correctly (§3.7).
- **Prior proofs:** annotations proved by another plug-in earlier in the same Frama-C session are not checked unless `-e-acsl-valid` is set (§2.6).

## Verified in the pipeline container

Checked on 2026-10-30 against a fresh `framac-pipeline:latest` build (Frama-C 33.0 Arsenic, `e-acsl-gcc`, clang, `-fsanitize=fuzzer`). The probe harnesses are main-less libFuzzer targets, each run on one violating and one benign input. They cover a heap overflow in the same function, a heap overflow in a callee, a use-after-free in a callee, a global array overflow, a stack buffer overflow in a callee, and an over-read of the fuzzer's input buffer.

- **`-n` is required for a main-less harness.** Without it, `e-acsl-gcc` writes the instrumented file and then links the original sources. That link fails with `undefined reference to 'main'` (`fail to compile/link un-instrumented code`), and the exit code is 1. With `-n`, the instrumented file is byte-identical and the exit code is 0.
- **Without `-M` and without `-main`, valid stack accesses are false alarms.** No `__e_acsl_store_block` is emitted for a local buffer that is only accessed through a callee's pointer, so `\valid(p + i)` fails on an in-bounds index. The other five probes behaved correctly: violation detected, benign input silent.
- **`-M`, or `-main LLVMFuzzerTestOneInput`, needs the runtime initialized.** Without initialization, every run segfaults in the runtime (`shadow_alloca`, `e_acsl_segment_tracking.c`), benign inputs included. libFuzzer's `main` is not instrumented and cannot do it, so a link-only object must define
  ```c
  int LLVMFuzzerInitialize(int *argc, char ***argv) {
      __e_acsl_memory_init(argc, argv, sizeof(void *));
      if (__e_acsl_globals_init) __e_acsl_globals_init();   /* declared __attribute__((weak)) */
      return 0;
  }
  ```
  This mirrors what E-ACSL inserts at the top of a real `main`.
- **With that hook, both `-n -M` and `-n -main LLVMFuzzerTestOneInput` are correct on all six probes.** Every violation is reported as `file:line: Error: Assertion failed:` (libFuzzer exit code 77), and every benign input runs clean.
- **The pipeline now uses `-n -M` plus the hook** (`templates/eacsl_runtime/fuzz_init.c`, linked in stage 2 by `run_eacsl_fuzz.py`, which every Make recipe calls). On the rebuilt image, the following all passed:
  - all six probes, built through the unmodified pipeline;
  - the selftest, with every check passing, including the new `benign_input_clean`;
  - a 21-second `campaign` on a bug-free harness: 542,981 executions, `clean`, `engine_used: eacsl`, RSS flat at 51 MB;
  - a `guardrail` run over that corpus: `passed_dynamic_oracle`.
- **`-rte-initialized @all` is now on in E-ACSL builds.** On the rebuilt image:
  - **Selftest:** every check passes, including the new `detects_uninitialized` (canary line 47, `canary_pick`).
  - **Generated harness with a real bug:** both benign inputs ran clean, and the uninitialized read was flagged at its exact line.
  - **Bug-free generated harness:** `campaign` was `clean` and `guardrail` gave `passed_dynamic_oracle`. Throughput was 3,336 exec/s with the checks and 7,459 without (`--no-rte-initialized`).
  - **The six probes above:** all six violations are still detected. Two benign inputs now raise false alarms, both from target code reading libFuzzer's `data` directly, which generated harnesses never do.
  - **Contract wrappers:** E-ACSL never marks the `__retres` of a generated `__gen_e_acsl_<fn>` wrapper initialized, so every `ensures` on `\result` failed `\initialized(&__retres)`. The build now inserts the missing `__e_acsl_initialize` between the two stages (`compile.wrapper_result_inits`). A deliberately false `ensures` is still rejected (`rejected_overconstrained`).
- **Failure reports:** Frama-C 33 prints the failing property's label (`rte/index_bound`, a named clause) on its own line and the predicate (`i < 8`) on the next. `parse_eacsl_failure` returns them separately (`label`, `predicate`), so a crash and an Eva red alarm on the same property share one fingerprint.
- **Measured noise of the other `--rte=all` checks** (not enabled): unsigned overflow flagged an FNV hash, unsigned downcast flagged a byte encoder, and signed downcast flagged a `(char)` cast of an input byte, all on benign inputs. A single alarm aborts the input, so the campaign stops there.
