# Slicing & Onboarding Large C Codebases (90,000+ LoC)

Feeding 90,000 lines of C directly into `frama-c -eva -main main` will fail on any real-world systems codebase: recursive data structures, dynamic allocation pools, and OS/network headers cause abstract state widening (`[-inf, +inf]`) and thousands of false alarms.

This guide explains how `/framac-slice` partitions a large multi-module codebase into tractable **module slices** and **30 to 80 LoC per-function WP proof tasks**:

- the modules are the build's **link units** (each library and executable), found by running the target's own build;
- a library with several entry families gets one harness per family, as a **sub-module** of its unit;
- a unit whose API reaches more than 400 functions or 15,000 lines is **split** into clusters around its entry points (`scripts/unit_split.py`), each with its own harness and Eva run.

---

## 1. Risk-Tier Classification Strategy

Not every module in a 90,000 LoC repository has the same code structure or threat exposure. `scripts/tiers.py` gives each function a tier from its **trust** (is it on a path attacker data can reach?) and its structure, and a module takes the most demanding tier among its functions:

- **Trust** comes from Phase 0's Frama-C model (`scripts/trust.py`): a library's API is untrusted by default, and so is everything an input reader (`read`, `recv`, `fread`, `getenv`, `main` with argv) reaches in the call graph. The structured threat model in `THREAT_MODEL.md` adds input sources and marks functions called only by trusted code.
- **Order:** no untrusted path, or an internal scalar helper, is Tier 3; heap allocation or recursion is Tier 2; a bounded output writer or formatter is Tier 1B; anything else on an untrusted path is Tier 1A.

The examples below show what each tier typically holds.

### Tier 1A: Untrusted Binary / Network Parsers (e.g., SNMPv3 ASN.1/BER Parser)
- **Code Characteristics:** Flat byte-array cursors (`const uint8_t *buf, size_t len`), bitwise tag/length decoding, nested TLV length validation, integer arithmetic (`offset + ber_len`), and cryptographic authentication gates (USM HMAC / AES).
- **Primary Vulnerability Classes:** Integer overflow in length checks (`offset + len` wrapping around in 32-bit math), out-of-bounds reads (`\valid_read`), uninitialized struct fields on truncated packets, and authentication bypass (`secLevel` confusion).
- **Verification Strategy:**
  1. **Phase 1 (`/framac-fuzz`):** 60-second `RTE + E-ACSL + LibFuzzer` burst catches immediate integer wraps and off-by-one TLV bounds.
  2. **Phase 2 (`/framac-eva`):** Module-level `Eva` from `eva_main()` with a symbolic 1,500-byte UDP payload (`Frama_C_make_unknown`) discharges ~85% of simple pointer checks.
  3. **Phase 3 (`/framac-wp`):** Full bottom-up Wavefront WP verification (`ber_decode_tag` -> `ber_decode_len` -> `ber_decode_oid` -> `snmpv3_parse_pdu`) plus the **Layer 4 auth-gate** and **Layer 6 secret-wipe** MetAcsl properties generated from the threat model ([`./security-properties.md`](./security-properties.md)).

### Tier 1B: Structured Packet / Log Emitters (e.g., Syslog RFC 5424 Formatter)
- **Code Characteristics:** Fixed-size output buffers (`char out_buf[1024]`), cursor accumulation (`pos += snprintf(out_buf + pos, cap - pos, ...)`), timestamp/PRI header serialization, and structured data escaping (`[SD-ID k="v"]`).
- **Primary Vulnerability Classes:** `snprintf` return-value misuse (advancing `pos` by the *would-have-written* length instead of actual written bytes, causing out-of-bounds writes on subsequent appends) and **Layer 5 CRLF / Delimiter Injection**.
- **Verification Strategy:**
  1. **Phase 1 & 2:** `E-ACSL + Fuzzing` and `Eva` immediately verify buffer cursor arithmetic on fixed-capacity arrays.
  2. **Phase 3 (`/framac-wp`):** Proves `0 <= pos < cap` loop invariants and the **Layer 5 output-sanitization** properties of the threat model's sinks (no CR or LF in log text).

### Tier 2: Recursive Heap & Tree Parsers (e.g., XML Configuration Parser)
- **Code Characteristics:** Recursive descent, dynamic heap allocation (`malloc`, `realloc`, `free`), doubly-linked DOM node trees, or third-party C libraries (`libxml2`, `expat`).
- **Why Deductive WP Should Not Be Used on DOM Trees:** Proving pointer separation (`\separated`) across arbitrary recursive heap graphs in SMT logic requires complex inductive separation predicates that do not scale.
- **Verification Strategy:**
  1. **Phase 1 (`/framac-fuzz`):** Build the XML module with `run_eacsl_fuzz.py campaign` (RTE + E-ACSL + `-fsanitize=fuzzer`) and fuzz with an XML dictionary (`-dict=xml.dict`). E-ACSL's shadow memory tracks every `malloc`/`free`, sub-struct array bound and initialized byte at runtime with zero ACSL annotations. Uninitialized reads are checked through `-rte-initialized`.
  2. **Boundary Decoupling for WP:** Once the XML parser populates a flat C configuration struct (`struct app_config`), run `/framac-wp` and `/framac-eva` on `config_validate(const struct app_config *cfg)` so all downstream modules enjoy mathematically proven configuration bounds!

### Tier 3: Internal Glue, IPC & State Machines (Remaining ~70k LoC)
- **Code Characteristics:** code no attacker data reaches (configuration, init and shutdown, logging), and scalar helpers without loops or pointers on an untrusted path (getters, small arithmetic).
- **Verification Strategy:** Eva only, no fuzzing; under the `quick` profile Tier 3 is deferred entirely. `python3 /opt/framac-pipeline/scripts/tiers.py summary` lists every Tier 3 function with its reason: check it before a `quick` run, since none of them is analysed. Onboard Tier 3 incrementally after the Tier 1A, 1B and Tier 2 boundaries are verified.

---

## 2. Capturing the Build

Frama-C needs exactly the files, include paths and macros each compilation unit was built with. Phase 0 gets them from the target's own build, not from reading the sources (`/framac-slice` Steps 1b and 1c):

1. **Recipe.** The user gives or confirms the build command, the Debian packages it needs, extra environment, and the test command. `build_capture.py propose` suggests one from the build files. It is stored in `run-metadata.json` (`run_metadata.py set-build`).
2. **Capture** (`build_capture.py run`, build image). The build runs under `bear` in a copy of the target on a per-run scratch volume, through `sandbox_exec.py`, with the broker's CPU lease as its job count. It records:
   - every compile, link and archive step, with build-system probes dropped;
   - the link units (libraries and executables) with their sources, the units they link, and per-file flags (`-I -D -U -include -imacros -iquote -isystem -std`);
   - test executables, marked `test` and left out of the analysis;
   - the API: exports (`nm -D`, version scripts), public headers, `main`;
   - a snapshot of the headers and libraries the build used from outside the project, for the analysis image.
3. **Stop and ask.** A build that fails stops Phase 0 with `needs_build_recipe` and a diagnostic: first error, missing headers, candidate packages. The user fixes the recipe, and the capture runs again.
4. **Model** (`phase0_model.py run`, analysis image). Frama-C parses each unit with its own flags, once per distinct set of sources and flags. A unit Frama-C cannot parse falls back to GCC's call graph and is flagged.

`build_callgraph_dag.py` turns the model into the DAG: one module per link unit, with its `required_sources`, `cppflags` and `force_includes`. The harness sidecars carry them into `pipeline_make.py gen`, which writes the per-module Make recipes.

---

## 3. Stubbing External Boundaries Once

Frama-C substitutes the host's `/usr/include` standard C library with its own ACSL-annotated standard library (`__fc_libc`), which already includes complete formal contracts for `<string.h>`, `<stdlib.h>`, `<stdio.h>`, `<stdint.h>`, and `<sys/socket.h>`.

For external third-party libraries (such as OpenSSL/mbedTLS in SNMPv3 or OS hardware abstractions):
1. **Never include third-party library `.c` files in a module slice.**
2. Include [`../templates/acsl/external_stubs.h`](../templates/acsl/external_stubs.h) or attach a concise ACSL contract to the external function's `.h` prototype:
   ```c
   /*@
     requires \valid_read(key + (0 .. key_len - 1));
     requires \valid_read(msg + (0 .. msg_len - 1));
     requires \valid(tag_out + (0 .. 15));
     requires \separated(tag_out + (0 .. 15), key + (0 .. key_len - 1), msg + (0 .. msg_len - 1));
     assigns tag_out[0 .. 15];
     ensures \result == 0 || \result == -1;
     ensures \result == 0 ==> \initialized(tag_out + (0 .. 15));
   */
   int external_hmac_sha256_96(
       const uint8_t *key, size_t key_len,
       const uint8_t *msg, size_t msg_len,
       uint8_t *tag_out
   );
   ```
This allows Frama-C (`Eva` and `WP`) to verify that *your* code passes valid, initialized, non-overlapping buffers into the cryptographic library and checks its return code, without ever analyzing the cryptographic library's internal math.
