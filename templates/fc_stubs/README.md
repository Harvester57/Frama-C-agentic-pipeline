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
- Checked-arithmetic builtins (`__builtin_add_overflow`, `_sub_`, `_mul_`, their `_p` forms and the
  typed `__builtin_sadd_overflow` ... `__builtin_umulll_overflow`). With Frama-C's own libc on a GCC
  machdep (Eva, WP, Phase 0), `FRAMAC_SHARE/libc/__fc_gcc_builtins.h` declares the typed forms with
  contracts and maps the generic ones onto them with `_Generic`; only the `_p` forms are missing. The
  E-ACSL frontend (host headers) knows none of them, calls them as undeclared functions, and clang
  refuses the redeclaration it prints. `fc_compat_types.h` therefore defines the `_p` forms for every
  Frama-C parse, and the others only under `__FRAMAC_EACSL__`. They are GNU statement expressions with
  GCC's semantics that never wrap or convert out of range, so they raise no alarm of their own. They
  must not be defined for a kernel-libc parse: this header is force-included first, so a macro for a
  typed form would break `__fc_gcc_builtins.h`'s declarations (`syntax error`). Frama-C's `_Generic`
  picks the typed form from the first operand's type only, so mixed operand types call the wrong one
  (`incompatible-types-call`); that is Frama-C's model, not changed here.
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
  the buffers of `read`, `recv`, `recvmsg` and `readv`, the bytes `strlcpy` and `strlcat` copied,
  and others. Results in libc's static
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
- `<sys/epoll.h>` and `<sys/inotify.h>` ([`./sys/epoll.h`](./sys/epoll.h), [`./sys/inotify.h`](./sys/inotify.h)):
  Frama-C's libc has neither header. Without these two, glibc's resolves through the `-idirafter` host
  directories and Frama-C stops on it (c-ares run-1 lost Eva and WP on its whole library:
  `sys/epoll.h:139: User Error: syntax error` on `__attr_access`, then `__sigset_t` and a second
  `struct timespec`; `sys/inotify.h:34` on `__flexarr`).
  - **Eva and WP** read the headers proposed upstream in pub/frama-c!56 (issue #2828), taken from
    [`../../docs/upstream/frama-c/patches/39-libc-linux-header-gaps.patch`](../../docs/upstream/frama-c/patches/39-libc-linux-header-gaps.patch):
    the Linux constants, `struct epoll_event` (packed, 12 bytes, as glibc on x86_64),
    `struct inotify_event`, and `epoll_create`, `epoll_create1`, `epoll_ctl`, `epoll_wait`,
    `epoll_pwait`, `inotify_init`, `inotify_init1`, `inotify_add_watch` and `inotify_rm_watch` with
    contracts. They never read glibc's header.
  - **One text with the patch.** From `__BEGIN_DECLS` to `__END_DECLS` each header is the patch's text,
    and `test_linux_event_headers_carry_the_text_of_the_upstream_patch` compares them: change the patch
    and the header together. Outside that text the header has no licence banner, `<...>` includes, and
    no `__PUSH_FC_STDLIB`.
  - **One pipeline addition**, marked in the header: `ensures result_bounded: -1 <= \result <= maxevents;`
    on `epoll_wait` and `epoll_pwait`. The patch states the result only inside the `full` and
    `partial_timeout_or_error` behaviors, whose `assumes` read the volatile `Frama_C_entropy_source`.
    WP gives each read of a volatile its own value, so it assumed neither behavior and a caller could
    not prove `n <= maxevents` (the index of `events[i]` in an event loop). Not yet in the merge request.
  - **Known Eva alarm.** In `n = epoll_wait(fd, ev, 8, t); for (i = 0; i < n; i++) use(ev[i]);` Eva
    reports `\initialized(&ev[i].events)` as Unknown: it joins the two behaviors and loses the link
    between `n` and the initialized prefix, as it does for `read()`. The preconditions are all valid.
  - **Not declared:** glibc's `epoll_pwait2`, and `struct epoll_params` with `EPIOCGPARAMS`,
    `EPIOCSPARAMS` and `EPOLL_IOC_TYPE`. Every other macro, function and struct of glibc 2.41's two
    headers is declared (compared with `gcc -dM -E` in the analysis image, 2026-11-18). A target that
    uses one of these gets `Calling undeclared function` or `Cannot resolve variable`; add it here,
    with a contract for the function (rule 5).
  - **`stub_gen.py`** classifies the nine functions `pipeline_stub`, so a run's overlay gets no block
    for them. A run directory made before this change may still hold `workspace/stubs/sys/epoll.h` or
    `sys/inotify.h` with its own contracts: Frama-C then prints `found two contracts ... Merging them`
    and keeps the first `\from` of each pair. Delete those two overlay files and rerun
    `pipeline_make.py run stubs stub-check`.
  - **E-ACSL** (host headers) gets glibc's header unchanged, through `#include_next`: the contracts
    name objects of Frama-C's libc (`__FC_MAX_OPEN_FILES`, `Frama_C_entropy_source`) that host headers
    do not have. They are therefore not checked against the real library at run time.
  - **When a release ships the headers**, these two files are no longer read: Frama-C's cpp command
    has `-I<share>/libc` before the pipeline's `-I.../templates/fc_stubs` (`-print-cpp-commands` in the
    analysis image). If the release ships the header as filed, `result_bounded` is lost with them:
    check WP on an event loop when the image moves to that release.
- `tests/test_fc_stub_repairs.py` checks these headers in the images: Eva on valid and short
  buffers, WP, E-ACSL against the real json-c, and the ABI (prototypes, constants, layouts)
  against glibc and json-c headers. libbsd is in neither image, so `strnstr`'s prototype is not
  checked against it. For epoll and inotify the sizes, offsets and all constants of glibc become
  `_Static_assert`s that Frama-C checks against the Eva / WP text; `stub_check.py shipped` compiles
  with gcc, which reads glibc's header on both sides, so it says nothing about that text.

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
- `TIOCM_LE` to `TIOCM_LOOP`: the modem-line bits of `TIOCMGET`/`TIOCMSET`, which glibc's
  `<sys/ioctl.h>` defines (`<bits/ioctl-types.h>`, as Linux `<asm-generic/termios.h>`) and
  `__fc_libc`'s does not (`Cannot resolve variable TIOCM_RTS`, libmodbus). Each one
  `#ifndef`-guarded.
- `TCGETS2`, `TCSETS2`, `TCSETSW2`, `TCSETSF2`: Linux's termios2 requests (custom baud rates),
  built with `_IOR`/`_IOW` above; `struct termios2` comes from the target's own
  `<asm/termbits.h>`. `__fc_libc`'s `<sys/ioctl.h>` stops at `TCGETS`/`TCSETS`.
- `explicit_bzero` and `memset_s`: missing from `__fc_libc`. Their postconditions state every
  written element (through `char` and `unsigned char`), so an L6 wipe through them proves without a
  loop: under WP Typed for a `char` array, under `Typed+cast` only for an `unsigned char` array.
  `FC_STUBS_NO_WIPE_DECLS` drops both declarations for a target that defines its own.
- `pipe2`, `getservbyname_r`, `getservbyport_r` and the `IN6_IS_ADDR_*` macros: missing from
  `__fc_libc`'s `<unistd.h>`, `<netdb.h>` and `<netinet/in.h>` (34.0~beta), which c-ares calls
  (run-2: `Calling undeclared function`, ten names `undeclared` in `stubs.json`). They are declared
  here and not in a header of their own, because Frama-C's `-I<share>/libc` comes before the
  pipeline's directories: a `templates/fc_stubs/netdb.h` would never be read.
  - **Stated twice.** Each contract gives its facts once in unconditional `ensures` (what WP uses: it
    learns nothing from behaviors whose `assumes` read the volatile `Frama_C_entropy_source`) and once
    in two behaviors (what lets Eva keep success apart from failure). Eva keeps them apart only with
    slevel: the pipeline's `-eva-slevel 100` gives `{-1}` with untouched ends on one side and two
    descriptors on the other; without slevel the two join and the idiom below gets Unknowns.
  - **`pipe2`:** result 0 or -1; on 0 both ends are initialized and in `0 .. __FC_MAX_OPEN_FILES - 1`;
    on -1 `pipefd` keeps its values, which a caller relies on when it presets both ends to -1 and
    closes what is not -1 afterwards. `__fc_libc`'s `pipe` says both ends are valid descriptors
    whatever the result, so that text was not copied. `flags` is not checked, and `errno` is not
    assigned: most contracts of `__fc_libc`'s `<unistd.h>` leave it out the same way (`// missing: may
    assign to errno`), so a caller that reads `errno` after a failure sees the value it had before.
    The two netdb functions return their error number.
  - **`getservbyname_r`, `getservbyport_r`** (glibc's six-argument form): the result is 0 or an error
    number, `*res` is NULL or `result_buf`, and it is NULL whenever the result is not 0. Not found is
    result 0 with a NULL `*res`, as glibc 2.41 does it. When `*res` is not NULL the four fields are
    initialized, `s_name` and `s_proto` are valid strings and `s_aliases` is readable; the `found`
    behavior adds that the three pointers lie inside `buf`. The last parameter is named `res` (glibc:
    `result`) because `tools/check_generated_text.py` reads a bare `result` in a contract as a mangled
    `\result`.
  - **Known Eva alarm.** `strlen(se.s_name)` after a found entry is Unknown
    (`precondition 'valid_string_s'`): Eva knows the pointer is inside `buf` but not that the bytes
    written there hold a NUL. WP has the fact (`found_strings`). `__fc_libc`'s `getpwnam_r` avoids this
    with static strings of its own, which a `_r` function with a caller buffer cannot use.
  - **The macros** are the twelve of POSIX `<netinet/in.h>` (`UNSPECIFIED`, `LOOPBACK`, `MULTICAST`,
    `LINKLOCAL`, `SITELOCAL`, `V4MAPPED`, `V4COMPAT` and the five `MC_*` scopes), five more than c-ares
    uses, so the family is whole. They read `s6_addr` bytes (the only member `__fc_libc`'s
    `struct in6_addr` has), evaluate their argument once, and are skipped when
    `IN6_IS_ADDR_UNSPECIFIED` is already defined (a later libc).
  - **Force-included headers.** Every Eva / WP parse now also reads `<netdb.h>` and
    `<netinet/in.h>` (`<unistd.h>`, `<sys/socket.h>` and `<string.h>` were already read). Define
    `FC_STUBS_NO_NETDB_DECLS` for a target whose own `struct servent`, `struct addrinfo` or
    `IN6_IS_ADDR_*` clash with them (it drops the two includes, the two functions and the macros),
    and `FC_STUBS_NO_PIPE2_DECL` for one that declares its own `pipe2`.
  - **Checked** by `test_libc_gap_names_in_eva_wp_and_against_glibc`: Eva on the c-ares idioms and on
    short, overlapping and NULL arguments, WP on callers, the three prototypes against glibc's with
    gcc, the twelve macros against glibc's on the same addresses, and the two netdb
    contracts as E-ACSL wrappers around the real glibc (found, not found, `ERANGE`), `pipe2` likewise
    (success and `EINVAL`). E-ACSL runs neither the three `\subset` clauses of each `found` behavior
    (the test program compares the pointers with the buffer itself) nor any `assigns`.
  - **When a release declares them.** The macros step aside (`#ifndef IN6_IS_ADDR_UNSPECIFIED`); the
    three functions do not. If `__fc_libc` gains `pipe2` (pub/frama-c#2828 asks for it) or the netdb
    pair, the kernel prints `found two contracts ... Merging them`, which the test above rejects:
    rename the libc declaration as for `getsockopt`, or drop this one.
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
