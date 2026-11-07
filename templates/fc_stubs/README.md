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
- Variadic calls without a libc specification produce `<fn>_fallback_<N>` symbols.
  `run_eacsl_fuzz.py` defines them in a generated, link-only `eacsl_fallbacks.o`. It forwards to
  the real function when it can; otherwise the call fails with `ENOSYS`, which is recorded in
  `variadic_fallbacks` as a coverage caveat. Never add those definitions to the instrumented
  sources: each definition shifts the fallback numbering.
- Host headers can use compiler types Frama-C rejects. The E-ACSL frontend therefore gets
  `-U__SIZEOF_INT128__` (`EACSL_DEFINES`), so `<linux/types.h>` skips its `__int128` typedefs.
- [`./errno.h`](./errno.h) maps `errno` to a tracked global under `__FRAMAC_EACSL__` only:
  glibc's thread-local errno is not E-ACSL-tracked memory, so every `errno = ...` would abort the
  runtime. errno values set by the real libc are not visible through it.

## Libc contract overrides (Eva / WP)

- `getsockopt`: `__fc_libc`'s behavior `other_options` requires `\valid(((char*)optval)+(0..))`,
  an unbounded range that no object satisfies, so every call with a non-null `optval` was
  Invalid. [`./fc_compat_types.h`](./fc_compat_types.h), force-included before any other header,
  renames the libc declaration and declares `getsockopt` with `optval` bounded by `*optlen`.
  Define `FC_STUBS_KEEP_LIBC_GETSOCKOPT` to keep the libc contract.
