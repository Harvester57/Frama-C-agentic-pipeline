# Frama-C third-party header stubs (`templates/fc_stubs/`)

Frama-C Eva and WP parse with Frama-C's own libc (`-nostdinc`), so headers installed in
`/usr/include` (`bsd/string.h`, `json-c/json.h`, `netinet/ip_icmp.h`, ...) are invisible to them.
The pipeline puts this directory first on the Frama-C include path and force-includes
[`./fc_compat_types.h`](./fc_compat_types.h):

- Eva / WP: via `augment_framac_cppflags()` in [`../../scripts/framac_common.py`](../../scripts/framac_common.py), which
  [`../../scripts/run_eva_slice.py`](../../scripts/run_eva_slice.py) and [`../../scripts/run_wp_function.py`](../../scripts/run_wp_function.py) (and therefore every Make recipe) apply;
- E-ACSL (host-header mode, `-no-frama-c-stdlib`): via `build_eacsl_flag_sets()` in
  [`../../scripts/eacsl_toolchain.py`](../../scripts/eacsl_toolchain.py), on the `-E` (Frama-C frontend) flags only.

## Rules

1. **Prototypes, types, macros and ACSL contracts only. Never C function bodies.** A body in a
   stub would be analysed as if it were the library, which makes the results depend on code
   nobody reviewed. Enforced by `test_fc_stub_headers_contain_no_function_bodies`.
   Every prototype has a contract with an `assigns` clause (otherwise Eva and WP use default
   `assigns` and a proof that calls the function is not sound). The stub contract lint test
   enforces it, and its allowlist is empty: write the contract, do not add an entry.
2. **Opaque handle types must be complete, and they are never dereferenced.** E-ACSL emits
   `alignof`/`sizeof` on pointed-to types, so `typedef struct json_object json_object;` alone
   fails to compile. Use one dummy member (`struct json_object { int _fc_opaque; };`). The
   library owns the real objects; target code that dereferences a handle is a target bug.
3. **Never define identifiers that belong to the target** (enum constants, target typedefs,
   target macros). The target headers are parsed after the stubs, and enum constants cannot be
   redefined.
4. **Nothing may be force-included into the backend compile.** The instrumented C file produced
   by E-ACSL is self-contained: it already contains every typedef it needs and has no `#include`
   lines. Re-including system headers into its Clang compile redefines `timeval`, `timespec`,
   `fd_set`, etc. For this reason:
   - `run_eacsl_fuzz.py` builds in two stages and gives the instrumented compile (`-e`) codegen
     flags only;
   - `fc_compat_types.h` is empty whenever `__FRAMAC__` is undefined.
5. **Declare every function the target calls.** A missing prototype makes Frama-C invent
   `int f()` (`Calling undeclared function`), which is unsound for Eva/WP, and makes Clang fail
   with `call to undeclared function`. The tool JSONs list these under `undeclared_functions`;
   add the prototype to the matching stub before trusting the results.
6. **Keep stubs consistent with the real library ABI** (argument and return types), because the
   E-ACSL binary links against the real library.

## E-ACSL notes

- E-ACSL cannot use Frama-C's libc (`unbounded ranges are not part of E-ACSL`, from its
  `string.h` specifications), so host-header mode is the only E-ACSL mode.
- In host-header mode, `fc_compat_types.h` simply includes glibc `<sys/types.h>`, so
  `__int32_t`, `u_short` and the others come from glibc and are identical by construction.
- Frama-C's parser knows `restrict` and `__restrict` but not GCC's `__restrict__`; Frama-C's
  libc maps it (`share/libc/features.h`), host glibc does not. The E-ACSL block of
  `fc_compat_types.h` therefore defines `__restrict__` as `__restrict` (guarded with `#ifndef`)
  ahead of its includes, so sources such as mpack's `MPACK_RESTRICT` parse. Clang compiles never
  see it (the header is empty without `__FRAMAC__`).
- Variadic calls without a libc specification produce `<fn>_fallback_<N>` symbols.
  `run_eacsl_fuzz.py` defines them in a generated, link-only `eacsl_fallbacks.o`. It forwards to
  the real function when it can; otherwise the call fails with `ENOSYS`, which is recorded in
  `variadic_fallbacks` as a coverage caveat. Never add those definitions to the instrumented
  sources: each definition shifts the fallback numbering.
- Host headers can use compiler types Frama-C rejects. The E-ACSL frontend therefore gets
  `-U__SIZEOF_INT128__` (`EACSL_DEFINES`), so `<linux/types.h>` skips its `__int128` typedefs.
- glibc's `<math.h>` turns `isnan`, `isinf`, `isfinite`, `isnormal`, `fpclassify` and `signbit`
  into `__builtin_*` calls Frama-C does not know (it prints K&R prototypes that clang then
  rejects), or into a `__MATH_TG` `_Generic` Frama-C rejects ("multiple compatible types").
  The E-ACSL frontend therefore gets `-D__SUPPORT_SNAN__` (glibc then uses the library forms)
  and [`./eacsl/math.h`](./eacsl/math.h), which `#include_next`s glibc's header and redefines
  `__MATH_TG` and `signbit` under `__FRAMAC_EACSL__`. Eva and WP never see either.
- [`./errno.h`](./errno.h) maps `errno` to a tracked global (`__fc_eacsl_errno`) under
  `__FRAMAC_EACSL__` only. glibc's errno lives in libc.so's TLS block, outside the TLS segment the
  E-ACSL runtime shadows (the executable's own block), so every `errno = ...` would abort the
  runtime (`Use of invalid address ... in unsafe_initialize`), and registering the address from
  `fuzz_init.c` crashes in `shadow_alloca` instead. libc never writes the global, so
  `run_eacsl_fuzz.py` links a generated, link-only errno shim (`<out>_errno_shim/eacsl_errno_shim.o`,
  `-Wl,--wrap=<fn>`) for the errno-setting libc functions the slice calls
  (`ERRNO_SHIM_FUNCTIONS` in [`../../scripts/eacsl_toolchain.py`](../../scripts/eacsl_toolchain.py)):
  each wrapper copies the global into libc's errno before the call and libc's errno back after it,
  so `errno == ERANGE` after `strtol` and `EINTR` after `read` take the right branch. The Variadic
  fallbacks sync the same way. The build result records the wrapped functions in `errno_shim`, a
  coverage caveat: after a libc call outside that list the target reads the last value it wrote.
  Add a function to the table (non-variadic, with its header) when a target branches on its errno.
- The same shim tells the E-ACSL runtime what a libc call wrote (`EACSL_LIBC_EFFECTS` in
  [`../../scripts/eacsl_toolchain.py`](../../scripts/eacsl_toolchain.py)), because E-ACSL runs on
  host headers without Frama-C's libc `assigns` clauses. Out-parameters get the written bytes marked
  initialized: `strto*`'s `endptr`, the socket address of `getsockname`, `accept` and `recvfrom`,
  the buffers of `read`, `recv`, `recvmsg` and `readv`, and others. Results in libc's static
  storage (`strerror`, `gmtime`, ...) are copied into a tracked buffer of the shim. Each entry is
  `(return type, parameter types, header, pre, post, copy)` in C. Add one when a target stops on
  `\initialized` right after a libc call, or on `unallocated` memory libc returned. A signature
  that differs from the host prototype makes the effects fail to compile; the shim then falls back
  to the errno wrappers alone and records `effects_error`.
- Memory that an uninstrumented library allocates (json-c objects and strings, `strdup`,
  `getenv`) is not tracked, so `\valid_read` is false on it. A stub contract that requires
  `\valid_read(p)` would reject every such pointer. The E-ACSL branches therefore check a string
  or buffer argument only when it lies in tracked memory (`\valid_read(s) ==> ...`), and they
  require handles only to be non-NULL, where the library asserts on NULL.
- E-ACSL 35 drops the first conjunct after the guard of a quantifier: in
  `\exists integer i; 0 <= i < n && P && Q` only `Q` is checked. Every E-ACSL quantifier in the
  stubs has a single predicate call after the guard (`... && __fc_bsd_cpy_fits(dst, src, size, i)`),
  which `test_eacsl_quantifiers_have_one_conjunct_after_the_guard` enforces.
- Ghost globals that are never defined (the json-c pools) carry libc's
  `__attribute__((__fc_stdlib_internal))` under `__FRAMAC__`, so E-ACSL does not register them in
  `__e_acsl_globals_init` (an undefined symbol at link time).
- E-ACSL checks `requires` only; it ignores `assigns`, and the stubs keep postconditions on
  library-owned results to the Eva / WP branch.

## Stub models

- `strlcpy` / `strlcat` ([`./fc_strlcpy.h`](./fc_strlcpy.h), included by `bsd/string.h` and by
  `fc_compat_types.h`): for Eva and WP the destination must hold `size` bytes
  (`\valid(dst + (0 .. size - 1))`), the source is a valid string, `strlcat`'s destination holds a
  string shorter than `size`, and the postconditions give the length, the copied prefix and the
  NUL. Under E-ACSL the destination check is exact: only the bytes actually written
  (`strlen(src) + 1`, bounded by `size`) must be valid, so a fuzz crash is always a real
  out-of-bounds write.
- `strnstr` (`bsd/string.h`): `little` is a valid string, `big` is readable up to `len` bytes or to
  its NUL; the result is NULL or inside `big`.
- json-c ([`./json-c/json.h`](./json-c/json.h), json-c 0.18): for Eva and WP, constructors return
  NULL or an element of the ghost pool `__fc_json_pool` (tokeners: `__fc_json_tokener_pool`), as
  `__fc_libc` does for `FILE`, so a handle used without its NULL check is an alarm. Returned
  strings point into the ghost buffer `__fc_json_strbuf` and are valid strings. Reference counts
  and the free in `json_object_put` are not modelled.
- `<netinet/ip_icmp.h>` follows glibc's layout and names, including the BSD ones (`struct icmp`
  with `icmp_ip` a `struct ip`, `ICMP_UNREACH`, `ICMP_TIMXCEED`, `ICMP_MASKREQ`, ...).
- `<sys/epoll.h>` and `<sys/inotify.h>` ([`./sys/epoll.h`](./sys/epoll.h), [`./sys/inotify.h`](./sys/inotify.h))
  are parse shims, not stubs: Frama-C's libc has neither header, so glibc's resolves through the
  `-idirafter` host directories, and it assumes glibc's `<sys/cdefs.h>` and `<bits/types/...>` guards
  (c-ares run-1 lost Eva and WP on its whole library: `sys/epoll.h:139: User Error: syntax error` on
  `__attr_access`, then `__sigset_t` and a second `struct timespec`; `sys/inotify.h:34` on `__flexarr`).
  For Eva and WP only, each defines what glibc's header needs under `#ifndef` (`__attr_access` and
  `__flexarr` as no-op / `[]`, dropped after the header; `__sigset_t` as Frama-C's `sigset_t`, so
  `epoll_pwait(..., &mask)` type-checks against `<signal.h>`; `_STRUCT_TIMESPEC`, so Frama-C's
  `struct timespec` stays the only one), then `#include_next`s glibc's header. They never include
  glibc's `<sys/cdefs.h>`, which redefines `__THROW`, `__nonnull`, ... for every later libc header.
  E-ACSL gets glibc's header unchanged. They declare nothing: the functions stay declared in glibc's
  header, `stub_gen.py` classifies them `host_header`, and its overlay `sys/epoll.h` (`#include_next`)
  reaches glibc through the shim.
- `tests/test_fc_stub_repairs.py` checks these headers in the images: Eva on valid and short
  buffers, WP, E-ACSL against the real json-c, and the ABI (prototypes, constants, layouts)
  against glibc and json-c headers. libbsd is in neither image, so `strnstr`'s prototype is not
  checked against it.

## Libc contract overrides (Eva / WP)

- `getsockopt`: `__fc_libc`'s behavior `other_options` requires `\valid(((char*)optval)+(0..))`,
  an unbounded range that no object satisfies, so every call with a non-null `optval` was
  Invalid. [`./fc_compat_types.h`](./fc_compat_types.h), force-included before any other header,
  renames the libc declaration and declares `getsockopt` with `optval` bounded by `*optlen`.
  Define `FC_STUBS_KEEP_LIBC_GETSOCKOPT` to keep the libc contract.
- `getopt`: `__fc_libc`'s contract assigns `*optarg` and nothing says where `optarg` points, so Eva
  gave a garbled mix for `optarg` and every `strcmp(optarg, ...)` or `argv[optind]` was Unknown.
  `-eva-use-spec` does not help (the function has no body either way); the kernel merges a second
  contract into the libc one, so the libc declaration is renamed like `getsockopt`'s. The override
  keeps `optarg` NULL or inside one of the `argv` strings and `optind` in `1 .. max(argc, 1)`.
  `optarg` stays possibly NULL after an option that takes an argument (the contract does not parse
  `optstring`), so a target that skips that check still gets one Unknown. Define
  `FC_STUBS_KEEP_LIBC_GETOPT` to keep the libc contract.
- `strlcpy`, `strlcat`: Frama-C 35's `<string.h>` declares them with its own contract, which the
  kernel merged with the stub's. The libc declarations are renamed and [`./fc_strlcpy.h`](./fc_strlcpy.h)
  declares them (see Stub models). Define `FC_STUBS_KEEP_LIBC_STRLCPY` to keep the libc contract.
- `syscall`: missing from `__fc_libc`'s `<unistd.h>`. Declared with `assigns \result \from number;`,
  the most ACSL can say about a variadic call: Eva and WP assume it writes no memory, so a buffer a
  syscall fills keeps the value the caller gave it. For the numbers that write memory,
  [`../../scripts/fc_cpp_wrapper.py`](../../scripts/fc_cpp_wrapper.py) rewrites a call with a constant
  x86_64 number into a typed declaration with a real contract: `syscall(SYS_read, ...)` becomes
  `__fc_syscall_read(...)`, likewise `recvfrom` and `getrandom`; each rewrite is logged
  (`[fc-cpp] <file>:<line>: syscall <name> rewritten`). The wrapper only rewrites when the text
  declares the target, so E-ACSL builds keep the real `syscall`. Other numbers keep the caveat.
- `_IO`, `_IOR`, `_IOW`, `_IOWR` and the `_IOC_*` helpers: Linux's ioctl request encoding, which
  glibc's `<sys/ioctl.h>` provides and `__fc_libc`'s does not (a struct-type argument was a syntax
  error). Generic-layout values, as on x86_64.
- `explicit_bzero` and `memset_s`: missing from `__fc_libc`. Their postconditions state every
  written element (through `char` and `unsigned char`), so an L6 wipe through them proves without a
  loop: under WP Typed for a `char` array, under `Typed+cast` only for an `unsigned char` array.
  `FC_STUBS_NO_WIPE_DECLS` drops both declarations for a target that defines its own.
- All of these sit in the `__fc_libc` branch only: E-ACSL builds take the real glibc declarations.
- The header assumes x86_64 LP64 (ioctl encoding, syscall numbers, `long` literals) and says so
  with a `_Static_assert` on `sizeof(long)` and `sizeof(void *)`: another machdep stops at parse time.
- **What to add next:** [`../../scripts/libc_gap_report.py`](../../scripts/libc_gap_report.py) lists, over
  the Phase 0 models of one or more runs, the external functions called that neither `__fc_libc` nor
  these stubs give a contract with `assigns` (run it in the analysis image, where it finds the libc
  through `frama-c -print-share-path`). Gaps come first, most-called first.
- `offsetof` is never redefined here. [`../../scripts/fc_cpp_wrapper.py`](../../scripts/fc_cpp_wrapper.py)
  repairs, in the preprocessed text, `offsetof` with a non-constant index and the null-pointer offset
  idiom `(size_t)&((T *)0)->m` (gperf tables), so `-warn-invalid-pointer` stays on.
