# Templates and stubs improvement plan (2026-11-10)

This plan covers everything under `templates/`: the harness template, `fc_stubs/`, `acsl/`, the E-ACSL runtime and canary, the MetAcsl templates and `pipeline.mk`. It comes from a read-through of those files and of [`troubleshooting.md`](troubleshooting.md) on 2026-11-10. Nothing in it has been run or tested yet: steps marked **diagnose** or **to test** need a repro in the analysis image before any fix lands.

It does not repeat work another plan owns:
- **A stdin entry style:** O10 in [`open-topics-remediation-plan.md`](open-topics-remediation-plan.md).
- **System headers from the build image:** O7 in the same plan. S2 below touches the same function (`augment_framac_cppflags`), so it goes after O7 or in the same worktree.
- **Confirming runs:** O6. H1 below adds one check to the libseccomp run.

## Priorities

- **P0:** a result can be wrong or silently optimistic, or a repair hint leads nowhere.
- **P1:** coverage or precision lost on targets already run, with no automatic workaround.
- **P2:** new checks and conveniences.
- **P3:** hygiene.

## Summary

| ID | Prio | Size | Topic | Depends on |
| :--- | :--- | :--- | :--- | :--- |
| D1 | P0 | S | Stale statements in the docs | H1 for one of them |
| S1 | P0 | S | Lint: every stub prototype has a contract | — |
| S2 | P0 | M–L | Per-run stub overlay, generated skeletons, hints that point to it | after O7 |
| S3 | P0 | M | Stub checks: ABI, Eva smoke, contract against the real library | S2 |
| S4 | P0 | M | Repair the shipped stubs (`bsd/string.h`, `json-c`, `ip_icmp.h`, `getopt`) | S1, decision 1 |
| M1 | P0 | M | Image acceptance test for every MetAcsl template variant | — |
| H1 | P0 | S | Land and confirm the `FRAMAC_FUZZ_COPY` and opaque-handle work | — |
| S5 | P1 | S–M | Real `errno` in E-ACSL builds (diagnose) | — |
| S6 | P1 | S–M | Typed `syscall` rewrites in `fc_cpp_wrapper.py` | — |
| S7 | P1 | S | libc gap report | — |
| M2 | P1 | S–M | `L5_no_crlf` on string literals | M1 |
| M3 | P1 | M | Generate Eva taint annotations for indirect secret flows | M1 |
| M4 | P1 | S | Do guardrail E-ACSL builds ever see `meta:` annotations? (diagnose) | — |
| H2 | P1 | M | Synthesized call sequences for handle types | H1 |
| K1 | P1 | S | `seeds` failures are recorded, not swallowed | — |
| S8 | P2 | S–M | One string vocabulary | — |
| S9 | P2 | S | Machdep assertions | — |
| M5 | P2 | S–M | L5 format-string property | decision 3 |
| M6 | P2 | S–M | L6 wipes: `explicit_bzero` contract, local secrets | S7 |
| M7 | P2 | S | L4: the gate sets the state only on success | decision 3 |
| H3 | P2 | S | Reject inputs the harness guard drops (`return -1`) | — |
| H4 | P2 | S | Exact input prefix in Eva for small sizes (to test) | H1 |
| C1 | P2 | S | Canary covers the post-processing passes it does not cover yet | S5 |
| K2 | P2 | S | Cache key per module for stub headers | S2 |
| K3 | P3 | S | `pipeline.mk` hygiene | — |

## Decisions for the user

1. **How strict is `strlcpy` under E-ACSL?** The stub requires `\valid(dst + (0 .. size - 1))`; the library writes at most `strlen(src) + 1` bytes. Strict flags a wrong `size` that happens not to overflow (a latent bug); exact never reports code that is not out of bounds. Recommendation: strict for Eva and WP, exact under `__FRAMAC_EACSL__`, so a fuzz crash is always a real out-of-bounds write.
2. **`templates/acsl/external_stubs.h`:** nothing includes it and no target calls its `fc_stub_*` functions. Recommendation: delete it once S2 lands and keep its HMAC contract as the worked example in `slicing-and-onboarding.md`.
3. **Threat-model schema:** M5 needs a `format` parameter on a sink, M7 a `success` value on an auth gate. Both are optional fields; say whether the schema may grow.

**Decided (user, 2026-11-10):** 1. split: strict for Eva and WP, exact under `__FRAMAC_EACSL__`. 2. delete `external_stubs.h` once S2 lands, keep its HMAC contract as the worked example. 3. the schema grows with both optional fields.

## Steps

### D1. Stale statements in the docs (P0, S)

- [`troubleshooting.md`](troubleshooting.md), entry "Many Eva Unknowns of One Kind": says "Fix: none yet" and marks A and B open, while the working tree implements both. Update it in the commit of H1.
- [`../templates/fc_stubs/README.md`](../templates/fc_stubs/README.md) and the troubleshooting entry on `<bsd/string.h>`: both say the stubs are "ACSL-annotated". `json-c/json.h` has no contract. Correct the text now; S4 makes it true.
- [`security-properties.md`](security-properties.md), Known Limits: "the generated Makefile does not run it". `pipeline.mk` has a `security-props` target and `seed` depends on it. Check the benchmark half of that sentence before rewriting it.

### S1. Lint: every stub prototype has a contract (P0, S)

- **Change:** a unit test next to `test_fc_stub_headers_contain_no_function_bodies`: every function prototype under `templates/fc_stubs/` is preceded by a contract with an `assigns` clause. An allowlist names the functions still without one, and S4 empties it.
- **Why first:** it turns "the stub has no contract" from something a run discovers (`unsound_proof`, default assigns in Eva) into something the suite refuses.

### S2. Per-run stub overlay, generated skeletons, hints that point to it (P0, M–L)

Today the Eva `repair_hints`, the WP `unsound_proof` message and three documents say "add a stub to `external_stubs.h`", a file nothing includes. A run has no place to put a contract for a function that only a host header declares.

- **Overlay:** `workspace/stubs/` is first on the Frama-C include path, before `templates/fc_stubs` (`augment_framac_cppflags` in `framac_common.py`, `build_eacsl_flag_sets` in `eacsl_toolchain.py`). The pipeline's own templates are never edited for one target.
- **Skeletons (deterministic, Make):** a new `scripts/stub_gen.py` reads the Phase 0 model, lists every external function called without a specification, and writes one header per library with the real prototypes and a conservative frame derived from the signature: `const` pointers are read only, each (pointer, length) pair bounds a range, everything else is `assigns \nothing` with a `TODO` marker that S1's lint rejects. New target `stubs`, after the model and before `reach-gate`.
- **Contracts (judgment, subagent):** a stub-author brief fills the `TODO`s from the library's documentation. The brief forbids function bodies and `ensures` the author cannot justify.
- **Ledger:** each stub contract is recorded as assumed, with the digest of its header, so a report can name what a proof rests on.
- **Hints:** `run_eva_slice.py` (`repair_hints`), `run_wp_function.py` (the `unsound_proof` message), the Eva and slice skills, `slicing-and-onboarding.md` and `make_wrapper_tips.md` point to `workspace/stubs/<lib>.h`.
- **Cache:** `cache.py` digests `scripts/` and `templates/` only. The overlay's digest must enter the key, or a changed stub replays a stale Eva or WP result.
- **Done when:** on a target that calls an unspecified external function, `stubs` writes the skeleton, the hint names it, and filling it removes the hint on the next run.

### S3. Stub checks (P0, M, after S2)

Three checks, for shipped stubs and for the overlay alike:

- **ABI (rule 6 of the README):** one translation unit per stub that includes the real header, then the stub's prototypes. A conflicting type is a compile error. Docker test for shipped stubs; part of `stub-check` for the overlay. This would have caught the `icmp_ip` divergence.
- **Eva smoke:** per stubbed function, a generated caller with one valid call (no alarm expected) and one call with a short buffer (alarm expected). A contract that accepts both is too weak.
- **Contract against the real library:** build the contract with E-ACSL, link the real library, fuzz the stubbed function directly. An `ensures` that fails there is a wrong contract. This is the dual-oracle guardrail applied to stubs. New target `stub-check`; a failing contract blocks the modules that include its header.

### S4. Repair the shipped stubs (P0, M, after S1 and decision 1)

- **`bsd/string.h`:**
  - `strlcpy`, `strlcat` and `strnstr` require a valid string for the source, not only a non-null pointer; `strlcat` also requires `dst` to hold a string within `size`.
  - `strlcpy` ensures the written prefix is initialized and NUL-terminated when `size > 0`, and bounds `\result`.
  - The `dst` range follows decision 1.
- **`json-c/json.h`:** a contract on every prototype. Handles come from a ghost pool, as Frama-C's libc does for `FILE`: `extern struct json_object __fc_json_pool[N];` and `ensures \result == \null || \subset(\result, &__fc_json_pool[0 .. N - 1])`. Returned strings point into a ghost buffer and are valid strings. Eva then has a precise, nullable result, so a missing NULL check in the target becomes an alarm. Add the missing API: `json_tokener_*`, `json_object_array_del_idx`, `json_type_to_name`.
- **`netinet/ip_icmp.h`:** `id_ip` holds a `struct ip` as in glibc; add the BSD names (`ICMP_UNREACH`, `ICMP_TIMXCEED`, `ICMP_MASKREQ` and their codes).
- **`getopt`:** a contract that keeps `optarg` inside `argv` (cause C of the libseccomp entry, 41 `strcmp` Unknowns). Check first whether `-eva-use-spec` is enough or the libc declaration has to be renamed as for `getsockopt`.
- **Done when:** S1's allowlist is empty and S3 passes on all four.

### S5. Real `errno` in E-ACSL builds (P1, S–M, diagnose)

`fc_stubs/errno.h` maps `errno` to a global, so the target never sees a value libc set: `errno == ERANGE` after `strtol` and `EINTR` after `read` take the wrong branch in the fuzz binary.

- **Diagnose:** does registering the real location in `fuzz_init.c` (`__e_acsl_store_block(__errno_location(), sizeof(int))` and `__e_acsl_full_init`) remove the `unsafe_initialize` abort? If so, the stub goes away.
- **Fallback:** `--wrap` shims in a link-only object, as for `eacsl_fallbacks.o`, that copy the real `errno` into the global after the calls that set it.
- **Either way:** while the shim exists, the build report records it (`errno_shim`), like `variadic_fallbacks`, so it shows as a coverage caveat.

### S6. Typed `syscall` rewrites (P1, S–M)

`syscall` has `assigns \result \from number`, so a buffer it fills keeps the caller's value. In `fc_cpp_wrapper.py`, rewrite `syscall(SYS_x, ...)` with a constant number into `__fc_syscall_x(...)` for the numbers that write memory (`getrandom`, `read`, `recvfrom`), each with a real contract in `fc_compat_types.h`. Other numbers keep today's contract and its caveat. Each rewrite is logged like the `offsetof` ones.

### S7. libc gap report (P1, S)

A script that lists, over the benchmark targets' models, the libc and Linux functions called that `__fc_libc` does not declare or leaves without a contract. Its output orders what `fc_compat_types.h` gains next and seeds S2's skeletons. Likely entries (`getrandom`, `explicit_bzero`, `reallocarray`, `memrchr`, `accept4`, `pipe2`) are a guess until it runs.

### S8. One string vocabulary (P2, S–M)

Three notions of a valid string coexist: libc's `valid_read_string`, the bounded E-ACSL predicates of the same name (limit 65536) in `fc_compat_types.h`, and `valid_c_string` over the recursive `c_strlen` in `acsl_vocabulary.h`. `L5_no_crlf` in the MetAcsl preamble and `no_crlf_or_nul` overlap too.

- Choose one name per notion and say for each whether E-ACSL can execute it.
- Drop `c_strlen` or define it from libc's `strlen` under `__fc_libc`.
- The prover brief and the knowledge base name only the canonical ones.

### S9. Machdep assertions (P2, S)

The ioctl encoding and the `long` literals of the `abs`/`labs` contracts assume x86_64 LP64. A `_Static_assert` on `sizeof(long)` in `fc_compat_types.h` makes another machdep fail at parse time.

### M1. Image acceptance test for every MetAcsl template variant (P0, M)

Only the wipe template has a test against the real MetAcsl (`test_wipe_acceptance_in_the_image`). The others are tested as text.

- **Change:** for each variant (`l4_auth_required` global and formal, `l4_auth_state` global and formal, `l5_sanitized` emit with text, bytes and object, and buffer, `l6_no_leak` calling and reading), a small program that satisfies the property and one that violates it. The first proves; the second leaves the named goal unproven. `FRAMAC_DOCKER_TESTS=1`.
- **Why P0:** a template MetAcsl rejects or instantiates as trivially true gives a ledger unit that means nothing, and no unit test can see it.

### M2. `L5_no_crlf` on string literals (P1, S–M)

Known limit: the property does not prove on a literal argument. Two options, in order:
1. `security_props.py` decides literal arguments itself from the model (a literal with no CR or LF satisfies the property) and emits no goal for them, recorded as decided syntactically.
2. Restate the predicate over libc's `strlen` and test whether the provers then discharge literals.

### M3. Eva taint annotations for indirect secret flows (P1, M)

`l6_no_leak` sees direct flows only, and the documentation says the pipeline does not generate the taint annotations. Generate them from the threat model into the work tree (ACSL only): `//@ taint` at each secret's source and `//@ assert !\tainted(...)` on each sink argument, and set the module's `EVA_TAINT`. The asserts get the property name `L6_no_leak_<secret>` so their status lands on the same ledger unit.

### M4. Do guardrail E-ACSL builds see `meta:` annotations? (P1, S, diagnose)

`L5_no_crlf` and the wipe predicates use unbounded quantifiers, which E-ACSL rejects. Check whether a guardrail build of a function carrying generated `meta:` assertions fails for that reason or strips them, and write the answer into the troubleshooting entry on unbounded quantifiers.

### M5. L5 format-string property (P2, S–M, decision 3)

For a sink with a `format` parameter (`syslog`, `fprintf`-like), the argument must be a string literal (CWE-134). Decided from the model, like M2 option 1; no MetAcsl goal.

### M6. L6 wipes (P2, S–M, after S7)

- A contract for `explicit_bzero` and `memset_s` whose postcondition states the zeroed range element by element, so a wipe through them proves under the Typed model (today only a loop with invariants does).
- Secrets held in a local: a wipe postcondition cannot name a local, so generate an assertion before each `return` of the owning function.
- Secrets of kind `return` stay a warning; say so in the report.

### M7. L4: the gate sets the state only on success (P2, S, decision 3)

A postcondition on the gate: when its result is not the `success` value, the state is unchanged. Without it a gate that sets the state on a failed check satisfies both existing properties.

### H1. Land and confirm the harness work in the tree (P0, S)

The working tree holds `FRAMAC_FUZZ_COPY` (fully initialized shadow for copies in `eva_main`) and constructor-built opaque handles, with tests. Commit it with the troubleshooting update of D1, and in the libseccomp confirming run (O6) compare the Unknown counts with the 97 `strcmp` and 44 alignment obligations of run-4.

### H2. Synthesized call sequences (P1, M, after H1)

Sequence cases exist only for chains recorded from the target's tests, at most 16. For a handle type with a constructor and a destructor and no recorded chain, generate one case that builds the handle, makes up to N calls chosen by input bytes among the functions taking that handle, then releases it. Single-call cases cannot reach lifecycle bugs (use after free, double free, call after error).

### H3. Reject inputs the harness guard drops (P2, S)

When a dispatch case's own length guard rejects the input, `LLVMFuzzerTestOneInput` returns `-1`, so libFuzzer keeps the corpus to inputs that reach the target. Check the clang version of the image supports it.

### H4. Exact input prefix in Eva for small sizes (P2, S, to test)

With a small `MAX_INPUT_SIZE`, `//@ split input_len;` in `eva_main` makes the initialized prefix exact per length, so an over-read of the input is a definite alarm in Eva too. Measure the cost on one module before making it a generator option.

### C1. Canary coverage (P2, S, after S5)

The canary does not exercise three things the build repairs or shims: a contract whose `ensures` reads `\result` (the wrapper result-init pass), a classification macro of `<math.h>` (`isnan`), and a write of `errno`. Add one statement for each on every input, so a regression fails `benign_input_clean`.

### K1. `seeds` failures are recorded (P1, S)

The `seeds` recipe and the two seed lines of `fuzz-%` start with `-`, and one ends in `|| true`. Seeds are optional, but a failure is invisible. Check what `seed_harvest.py write` and `fuzz_assets.py write` leave on failure, then make each write a status the fuzz report carries (`seeds: failed, reason`), keeping the recipe non-blocking.

### K2. Cache key per module for stub headers (P2, S, after S2)

One digest over all of `templates/` means any stub edit invalidates every cached result. Key each module on the stub headers its preprocessing actually reads.

### K3. `pipeline.mk` hygiene (P3, S)

- `module-%` repeats the `facts-%` recipe: one `define`.
- `help` omits `eva-tune-base`.
- New targets `stubs` and `stub-check` in `.PHONY`, `help` and the order `pipeline_make.py run` enforces.

## Order and parallelism

1. **First, in parallel:** D1, S1, M1, H1, K1, M4, S5 (diagnosis). Their files are disjoint.
2. **Then:** S2, which owns `framac_common.py`, `eacsl_toolchain.py`, `cache.py` and the hint texts; S7 alongside it.
3. **After S2, in parallel:** S3 (new test and check scripts), S4 (the stub headers), K2 and K3 (`cache.py`, `pipeline.mk`).
4. **Independent of the stub track:** S6 (`fc_cpp_wrapper.py`), M2, M3, M5–M7 (`security_props.py`, one after another), H2–H4 (`api_harness.py` and the template, one after another), S8, S9, C1.

The rules of [`open-topics-remediation-plan.md`](open-topics-remediation-plan.md#rules-for-every-step) apply: checks after each step, docs and skills in the same commit, code steps in the worktree, each step updates its troubleshooting entry.

## Not planned

- Contracts for whole libraries nobody has run a target against (zlib, OpenSSL): S2 generates what a target needs when it needs it.
- Replacing host-header mode for E-ACSL: the reasons in the stub README still hold.
