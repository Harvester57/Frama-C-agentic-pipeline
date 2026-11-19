# Slicing & Onboarding Large C Codebases

The pipeline is designed for codebases of up to about 100,000 lines. That size is a design goal: the [Project Status](../../README.md#project-status) section of the README shows what recent runs achieved.

Feeding a large codebase directly into `frama-c -eva -main main` will fail on most real-world systems code: recursive data structures, dynamic allocation pools, and OS/network headers cause abstract state widening (`[-inf, +inf]`) and thousands of false alarms.

This guide explains how `/framac-slice` partitions a large multi-module codebase into tractable **module slices** and **per-function WP proof tasks**:

- the modules are the build's **link units** (each library and executable), found by running the target's own build;
- a library with several entry families gets one harness per family, as a **sub-module** of its unit;
- a unit whose API reaches more than 400 functions or 15,000 lines is **split** into clusters around its entry points (`scripts/unit_split.py`), each with its own harness and Eva run. Clusters merge only while they stay within those limits. With the Phase 0 model's address-flow facts, an indirect call follows only the candidates whose address the reached code takes or reads from a global's initializer. Each such cluster then builds from its own files (`build_sources`), and link repair stubs what those files name outside them ([`../plans/unit-split-address-flow.md`](../plans/unit-split-address-flow.md)).

---

## 1. Risk-Tier Classification Strategy

Not every module in a large repository has the same code structure or threat exposure. `scripts/tiers.py` gives each function a tier from its **trust** (is it on a path attacker data can reach?) and its structure, and a module takes the most demanding tier among its functions:

- **Trust** comes from Phase 0's Frama-C model (`scripts/trust.py`): a library's exported API is untrusted by default (functions defined in its public headers are harnessed entry points, but untrusted only when the threat model or CodeQL marks them, or an input reader reaches them), and so is everything an input reader (`read`, `recv`, `fread`, `getenv`, `main` with argv) reaches in the call graph. The structured threat model in `THREAT_MODEL.md` adds input sources and marks functions called only by trusted code.
- **Order:** no untrusted path, or an internal scalar helper, is Tier 3; heap allocation or recursion is Tier 2; a bounded output writer or formatter is Tier 1B; anything else on an untrusted path is Tier 1A.

The examples below show what each tier typically holds.

### Tier 1A: Untrusted Binary / Network Parsers (e.g., SNMPv3 ASN.1/BER Parser)
- **Code Characteristics:** Flat byte-array cursors (`const uint8_t *buf, size_t len`), bitwise tag/length decoding, nested TLV length validation, integer arithmetic (`offset + ber_len`), and cryptographic authentication gates (USM HMAC / AES).
- **Primary Vulnerability Classes:** Integer overflow in length checks (`offset + len` wrapping around in 32-bit math), out-of-bounds reads (`\valid_read`), uninitialized struct fields on truncated packets, and authentication bypass (`secLevel` confusion).
- **Verification Strategy:**
  1. **Phase 1 (`/framac-fuzz`):** An `RTE + E-ACSL + LibFuzzer` campaign of 60 (`quick`), 120 (`standard`) or 900 (`deep`) CPU-seconds per harness case catches immediate integer wraps and off-by-one TLV bounds.
  2. **Phase 2 (`/framac-eva`):** Module-level `Eva` from `eva_main()` with a symbolic 1,500-byte UDP payload (`Frama_C_make_unknown`) discharges most simple pointer checks.
  3. **Phase 3 (`/framac-wp`):** Full bottom-up Wavefront WP verification (`ber_decode_tag` -> `ber_decode_len` -> `ber_decode_oid` -> `snmpv3_parse_pdu`) plus the **Layer 4 auth-gate** and **Layer 6 secret-wipe** MetAcsl properties generated from the threat model ([`./security-properties.md`](./security-properties.md)).

### Tier 1B: Structured Packet / Log Emitters (e.g., Syslog RFC 5424 Formatter)
- **Code Characteristics:** Fixed-size output buffers (`char out_buf[1024]`), cursor accumulation (`pos += snprintf(out_buf + pos, cap - pos, ...)`), timestamp/PRI header serialization, and structured data escaping (`[SD-ID k="v"]`).
- **Primary Vulnerability Classes:** `snprintf` return-value misuse (advancing `pos` by the *would-have-written* length instead of actual written bytes, causing out-of-bounds writes on subsequent appends) and **Layer 5 CRLF / Delimiter Injection**.
- **Verification Strategy:**
  1. **Phase 1 & 2:** `E-ACSL + Fuzzing` and `Eva` immediately verify buffer cursor arithmetic on fixed-capacity arrays.
  2. **Phase 3 (`/framac-wp`):** Proves `0 <= pos < cap` loop invariants and the **Layer 5 output-sanitization** properties of the threat model's sinks (no CR or LF in log text).

### Tier 2: Recursive Heap & Tree Parsers (e.g., XML Configuration Parser)
- **Code Characteristics:** Recursive descent, dynamic heap allocation (`malloc`, `realloc`, `free`), doubly-linked DOM node trees, or third-party C libraries (`libxml2`, `expat`).
- **Why Deductive WP Should Not Be Used on DOM Trees:** Proving pointer separation (`\separated`) across arbitrary recursive heap graphs in SMT logic requires complex inductive separation predicates that do not scale. The scheduler still queues WP for every Tier 2 function, so expect such proofs to stall.
- **Verification Strategy:**
  1. **Phase 1 (`/framac-fuzz`):** Build the XML module with `run_eacsl_fuzz.py campaign` (RTE + E-ACSL + `-fsanitize=fuzzer`) and fuzz with an XML dictionary (`-dict=xml.dict`). E-ACSL's shadow memory tracks every `malloc`/`free`, sub-struct array bound and initialized byte at runtime with zero ACSL annotations. Uninitialized reads are checked through `-rte-initialized`.
  2. **Boundary Decoupling for WP:** Once the XML parser populates a flat C configuration struct (`struct app_config`), run `/framac-wp` and `/framac-eva` on `config_validate(const struct app_config *cfg)` so all downstream modules enjoy mathematically proven configuration bounds!

### Tier 3: Internal Glue, IPC & State Machines
- **Code Characteristics:** code no attacker data reaches (configuration, init and shutdown, logging), and scalar helpers without loops or pointers on an untrusted path (getters, small arithmetic).
- **Verification Strategy:** A Tier 3 module gets Eva and, outside `quick`, WP on its `rte` units, with no fuzzing. Under `quick`, Tier 3 modules are skipped and every Tier 3 function's units are deferred, though a Tier 3 function inside a higher-tier module is still fuzzed and run through Eva with that module. `python3 /opt/framac-pipeline/scripts/tiers.py summary` lists every Tier 3 function with its reason: check it before a `quick` run. Onboard Tier 3 incrementally after the Tier 1A, 1B and Tier 2 boundaries are verified.

---

## 2. Capturing the Build

Frama-C needs exactly the files, include paths and macros each compilation unit was built with. Phase 0 gets them from the target's own build, not from reading the sources (`/framac-slice` Steps 1b and 1c):

1. **Recipe.** The user gives or confirms the build command, the Debian packages it needs, extra environment, and the test command. `build_capture.py propose` suggests one from the build files. It is stored in `run-metadata.json` (`run_metadata.py set-build`).
2. **Capture** (`build_capture.py run`, build image). The build runs under `bear` in a copy of the target on a per-run scratch volume, through `sandbox_exec.py`, with the broker's CPU lease as its job count. It records:
   - every compile, link and archive step, with build-system probes dropped;
   - the link units (libraries and executables) with their sources, the units they link, and per-file flags (`-I -D -U -include -imacros -iquote -isystem -std`);
   - test executables, marked `test` and left out of the analysis;
   - the API: exports (`nm -D`, version scripts), public headers, `main`;
   - a snapshot of the headers and libraries the build used from outside the project, for the analysis image. It also holds the build image's copies of the libc headers Frama-C's libc lacks (`linux-libc-dev`'s `linux/*` and `asm/*`, glibc's `elf.h`), under `libc/`. Every Frama-C parse searches them with `-idirafter`, after the target's headers and before the analysis image's own `/usr/include` directories. Those image directories stay last, as the fallback for a capture made before this export and for libc headers the build never named. `target_env.with_include_flags` owns this order.
3. **Stop and ask.** A build that fails stops Phase 0 with `needs_build_recipe` and a diagnostic: first error, missing headers, candidate packages. The user fixes the recipe, and the capture runs again. A host that is not x86_64, or a build that produces other code than x86_64 (`-m32`, `-mx32`, a cross compiler), stops Phase 0 with `unsupported_architecture` and instructions: x86_64 Linux is the only supported platform.
4. **Model** (`phase0_model.py run`, analysis image). Frama-C parses each unit with its own flags, once per distinct set of sources and flags. A unit Frama-C cannot parse falls back to GCC's call graph and is flagged. Such a unit is fuzzed with the sanitizers only: Eva and WP cannot run on it, and its planned units are deferred.

`build_callgraph_dag.py` turns the model into the DAG: one module per link unit, with its `required_sources`, `cppflags` and `force_includes`. The harness sidecars carry them into `pipeline_make.py gen`, which writes the per-module Make recipes.

---

## 3. Stubbing External Boundaries Once

Frama-C substitutes the host's `/usr/include` standard C library with its own ACSL-annotated standard library (`__fc_libc`), which already includes complete formal contracts for `<string.h>`, `<stdlib.h>`, `<stdio.h>`, `<stdint.h>`, and `<sys/socket.h>`.

For external third-party libraries (such as OpenSSL/mbedTLS in SNMPv3 or OS hardware abstractions), never include the library's `.c` files in a module slice. Give each external function the target calls a contract instead, in one of three places, decided by where its prototype is declared:

- **Frama-C's libc and `templates/fc_stubs/`** already carry contracts (`bsd/string.h`, `eacsl/math.h`, `errno.h`, `fc_compat_types.h`, `fc_strlcpy.h`, `json-c/json.h`, `netinet/ip_icmp.h`, `sys/epoll.h`, `sys/inotify.h`). They are the pipeline's, never edited for one target.
- **A header of the project:** the contract goes on that prototype in `workspace/work/`, as any ACSL edit.
- **A host header (a package the build used):** the run's stub overlay, `workspace/stubs/<lib>.h` (step S2 of [`../plans/templates-and-stubs-improvement-plan.md`](../plans/templates-and-stubs-improvement-plan.md)).

`scripts/libc_gap_report.py` lists the external functions that have no contract with an `assigns` clause in Frama-C's libc or `templates/fc_stubs/`. Run it by hand: Make does not.

The overlay works in two halves:

1. **Skeletons (Make, `pipeline_make.py run stubs`, after the model and before `reach-gate`):** `scripts/stub_gen.py run` reads the Phase 0 model (`externals`, `external_decls`) and writes, for every external a host header declares, a block in `workspace/stubs/<name>`, where `<name>` is how the target includes that header (`json-c/json.h`, `gcrypt.h`). The overlay header includes the real one (`#include_next`), then redeclares the functions with their contracts. It is first on the include path of every Frama-C parse (`augment_framac_cppflags`) and of the E-ACSL frontend (`build_eacsl_flag_sets`). A skeleton has the real prototype and a frame derived from the signature (const pointers read only, a pointer and its length bound a range), and stays under `#ifdef FC_STUB_DRAFT` with a `TODO(stub-author)` line: inactive until filled. `stub_gen.py run` never rewrites an existing block, and its report, `workspace/reports/stubs.json`, gives each header's digest and each function's state (`draft`, `incomplete`, `filled`, or `manual` for a header written without the markers).
2. **Contracts (a subagent):** one stub author per overlay header, briefed with `stub_gen.py brief --header workspace/stubs/<name>` ([`../../skills/framac-slice/stub_author_brief.md`](../../skills/framac-slice/stub_author_brief.md)), fills the contracts from the library's documentation and removes the guard. No function bodies, and no `ensures` the documentation does not justify.
3. **Checks (Make, `pipeline_make.py run stub-check`, after `stubs` and before `seed`):** `scripts/stub_check.py run` writes `workspace/reports/stub_check.json`. Per overlay header: an **ABI** check (one translation unit including the header, drafts included, so a redeclared prototype that conflicts with the real one is a compile error); an **Eva smoke** check (per function, a generated caller with one valid call, which must raise no precondition alarm, and, for a buffer with its length or a fixed-size array, a call one element short, which must raise one: a contract that accepts both is `too_weak`); and a **dynamic** check (the same valid calls, lengths and contents varied, built with E-ACSL and linked with the real library the calling modules link, one sandboxed process per function: a failed `ensures` is `violated` when the call's arguments were genuine. It is `inconclusive` when the driver fabricated a handle or structure for a pointer parameter (`fabricated_argument`), or when every failing term is a memory predicate on memory the uninstrumented library owns (`untracked_library_memory`)). A header fails on a problem in the stub report, an `assigns` location other than `\result` without `\from`, a failed ABI check, a Frama-C error, an E-ACSL `annot-error` in the header, or a violated contract. The Phase 0 gate (`phase0_gates.py`) refuses every module whose DAG `external_callees` name one of its functions, with its lexer and sub-modules, until a stub-check of the fixed header passes. Eva warnings and inconclusive dynamic checks are reported, never blocking.

Every active stub contract is an assumption, not a result: `ledger.py record-stub-contracts` (run by `stubs`, `stub-check` and `seed`) records it as a `stub_contract` assumption, with the header's digest and what stub-check found for that same content, on the units of every function that calls it. The cache keys of Eva and of the E-ACSL builds include the overlay headers each module reads, so a changed contract never replays a stale result.

Worked example: the target calls `external_hmac_sha256_96` from `<crypto/hmac.h>`. After the author, `workspace/stubs/crypto/hmac.h` holds:

```c
#pragma once
#include_next <crypto/hmac.h>

/* fc-stub: external_hmac_sha256_96 */
/*@
  requires valid_key: key_len > 0 ==> \valid_read(key + (0 .. key_len - 1));
  requires valid_msg: msg_len > 0 ==> \valid_read(msg + (0 .. msg_len - 1));
  requires init_key: key_len > 0 ==> \initialized(key + (0 .. key_len - 1));
  requires init_msg: msg_len > 0 ==> \initialized(msg + (0 .. msg_len - 1));
  requires valid_tag: \valid(tag_out + (0 .. 15));
  requires sep: \separated(tag_out + (0 .. 15), key + (0 .. key_len - 1), msg + (0 .. msg_len - 1));
  assigns tag_out[0 .. 15], \result \from key[0 .. key_len - 1], msg[0 .. msg_len - 1], key_len, msg_len;
  ensures status: \result == 0 || \result == -1;
  ensures init_tag: \result == 0 ==> \initialized(tag_out + (0 .. 15));
*/
extern int external_hmac_sha256_96(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len,
                                   uint8_t *tag_out);
```

This allows Frama-C (`Eva` and `WP`) to verify that *your* code passes valid, initialized, non-overlapping buffers into the cryptographic library and checks its return code, without ever analyzing the cryptographic library's internal math.

Limits: a header the library includes only through a quoted sibling include (`#include "hmac_impl.h"` inside `hmac.h`) is never looked up on the include path, so `stub_gen.py` shadows the sibling that includes it; a translation unit that includes the inner header directly then sees no contract. A function called without any prototype is listed as `undeclared` in the report: a header is missing from the module's flags. Stub-check generates calls only for prototypes it can call generically (no variadic or function-pointer parameter, `not_callable` in its report), fills every buffer with 64 bytes, and needs the library in the snapshot: a function whose arguments need a real object (an opened handle, a parsed context) gets an `inconclusive` or `driver_rejected` dynamic check, never a pass. Module fuzzing does not check stub contracts at all (see the troubleshooting entry on stub-check).

`stub_check.py shipped` runs the ABI check on the pipeline's own `templates/fc_stubs`: per stub, its prototypes after the real header, and a layout probe of every struct it defines, built once against the real header and once against the stub, which must agree on each member's offset, size and type class (it finds `icmp_ip`, a struct in glibc and an array in `netinet/ip_icmp.h`).
