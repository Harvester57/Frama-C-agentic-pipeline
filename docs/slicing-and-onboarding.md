# Slicing & Onboarding Large C Codebases (90,000+ LoC)

Feeding 90,000 lines of C directly into `frama-c -eva -main main` will fail on any real-world systems codebase: recursive data structures, dynamic allocation pools, and OS/network headers cause abstract state widening (`[-inf, +inf]`) and thousands of false alarms.

This guide explains how `/framac-slice` partitions a large multi-module codebase into tractable **100 to 3,000 LoC module slices** and **30 to 80 LoC per-function WP proof tasks**.

---

## 1. Risk-Tier Classification Strategy

Not every module in a 90,000 LoC repository has the same code structure or threat exposure. `build_callgraph_dag.py` classifies modules into four tiers:

### Tier 1A: Untrusted Binary / Network Parsers (e.g., SNMPv3 ASN.1/BER Parser)
- **Code Characteristics:** Flat byte-array cursors (`const uint8_t *buf, size_t len`), bitwise tag/length decoding, nested TLV length validation, integer arithmetic (`offset + ber_len`), and cryptographic authentication gates (USM HMAC / AES).
- **Primary Vulnerability Classes:** Integer overflow in length checks (`offset + len` wrapping around in 32-bit math), out-of-bounds reads (`\valid_read`), uninitialized struct fields on truncated packets, and authentication bypass (`secLevel` confusion).
- **Verification Strategy:**
  1. **Phase 1 (`/framac-fuzz`):** 60-second `RTE + E-ACSL + LibFuzzer` burst catches immediate integer wraps and off-by-one TLV bounds.
  2. **Phase 2 (`/framac-eva`):** Module-level `Eva` from `eva_main()` with a symbolic 1,500-byte UDP payload (`Frama_C_make_unknown`) discharges ~85% of simple pointer checks.
  3. **Phase 3 (`/framac-wp`):** Full bottom-up Wavefront WP verification (`ber_decode_tag` -> `ber_decode_len` -> `ber_decode_oid` -> `snmpv3_parse_pdu`) plus **Layer 4 Ghost Auth State** and **Layer 6 Secret Zeroization**.

### Tier 1B: Structured Packet / Log Emitters (e.g., Syslog RFC 5424 Formatter)
- **Code Characteristics:** Fixed-size output buffers (`char out_buf[1024]`), cursor accumulation (`pos += snprintf(out_buf + pos, cap - pos, ...)`), timestamp/PRI header serialization, and structured data escaping (`[SD-ID k="v"]`).
- **Primary Vulnerability Classes:** `snprintf` return-value misuse (advancing `pos` by the *would-have-written* length instead of actual written bytes, causing out-of-bounds writes on subsequent appends) and **Layer 5 CRLF / Delimiter Injection**.
- **Verification Strategy:**
  1. **Phase 1 & 2:** `E-ACSL + Fuzzing` and `Eva` immediately verify buffer cursor arithmetic on fixed-capacity arrays.
  2. **Phase 3 (`/framac-wp`):** Proves `0 <= pos < cap` loop invariants and **Layer 5 Output Sanitization** postconditions (`no_crlf_or_nul(out_buf, \result)`).

### Tier 2: Recursive Heap & Tree Parsers (e.g., XML Configuration Parser)
- **Code Characteristics:** Recursive descent, dynamic heap allocation (`malloc`, `realloc`, `free`), doubly-linked DOM node trees, or third-party C libraries (`libxml2`, `expat`).
- **Why Deductive WP Should Not Be Used on DOM Trees:** Proving pointer separation (`\separated`) across arbitrary recursive heap graphs in SMT logic requires complex inductive separation predicates that do not scale.
- **Verification Strategy:**
  1. **Phase 1 (`/framac-fuzz`):** Build the XML module with `run_eacsl_fuzz.py campaign` (RTE + E-ACSL + `-fsanitize=fuzzer`) and fuzz with an XML dictionary (`-dict=xml.dict`). E-ACSL's shadow memory tracks every `malloc`/`free`, sub-struct array bound and initialized byte at runtime with zero ACSL annotations. Uninitialized reads are checked through `-rte-initialized`.
  2. **Boundary Decoupling for WP:** Once the XML parser populates a flat C configuration struct (`struct app_config`), run `/framac-wp` and `/framac-eva` on `config_validate(const struct app_config *cfg)` so all downstream modules enjoy mathematically proven configuration bounds!

### Tier 3: Internal Glue, IPC & State Machines (Remaining ~70k LoC)
- **Verification Strategy:** Onboard incrementally after Tier 1A, 1B, and Tier 2 boundaries are verified. Use spot `Eva` analyses on state-machine entry points.

---

## 2. Extracting the Build Graph (`compile_commands.json`)

Frama-C requires exact `-I` include paths and `-D` preprocessor defines for each compilation unit.

### CMake Projects
```bash
cmake -B build "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"
```

### Make / Autotools Projects (Inside `framac-pipeline` Container)

The target is mounted read-only, so the build runs in a disposable copy inside the run directory, through `sandbox_exec.py` (rlimits, env allowlist, timeout):

```powershell
# Windows (PowerShell)
& ".\wrappers\framac-docker.ps1" `
  -TargetDir "C:\path\to\c-project" -RunDir "<run-dir>" `
  "mkdir -p workspace/build-scratch && cp -a /target/. workspace/build-scratch/ && python3 /opt/framac-pipeline/scripts/sandbox_exec.py run --writable workspace/build-scratch --cwd workspace/build-scratch -- bear -- make -j`$FRAMAC_JOB_CPUS"
```

```bash
# Linux / macOS (POSIX)
./wrappers/framac-docker.sh \
  --target /path/to/c-project --run-dir "<run-dir>" \
  -- 'mkdir -p workspace/build-scratch && cp -a /target/. workspace/build-scratch/ && python3 /opt/framac-pipeline/scripts/sandbox_exec.py run --writable workspace/build-scratch --cwd workspace/build-scratch -- bear -- make -j$FRAMAC_JOB_CPUS'
```

`FRAMAC_JOB_CPUS` is the number of CPUs the broker leased to this container, so the build uses the whole lease and no more. In PowerShell the backtick keeps `$FRAMAC_JOB_CPUS` for the container's shell; in the POSIX wrapper, single-quote the command instead.

Once `compile_commands.json` exists, `build_callgraph_dag.py` automatically extracts per-file `-I` and `-D` flags into each module's `cppflags`. The harness sidecars carry them into `pipeline_make.py gen`, which writes the per-module Make recipes.

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
