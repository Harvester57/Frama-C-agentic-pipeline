# Bugs Found by the Frama-C Verification Pipeline

- **Repository Root:** [`../../README.md`](../../README.md)

This directory catalogs software defects and undefined behaviors discovered and independently verified using the **Frama-C Agentic Verification & Hybrid Fuzzing Pipeline** across open-source C targets.

Every entry listed here has passed the pipeline's **Crash Verification Gate**:
1. **Dynamic Witness:** Triggered at runtime by a concrete input under Frama-C `RTE + E-ACSL` shadow-memory/arithmetic instrumentation (`e-acsl-gcc`) and/or Clang `ASan + UBSan` (`-fsanitize=address,undefined -fno-sanitize-recover=all`), replayed deterministically inside the hardened container.
2. **Contract & Precondition Audit:** An independent Crash Verifier subagent audited the harness against the target function's documented API preconditions to rule out harness-induced faults (`harness_induced`), environment artifacts (`tooling_env`), and unreachable internal states.
3. **Root-Cause & Remediation Trace:** Source-level trace from the public entry point to the failing operation, paired with a minimal standalone reproducer and a candidate fix diff suitable for upstream disclosure.

> [!NOTE]
> For bugs discovered in **Frama-C 33.0 / 34.0~~dev and `e-acsl-gcc` itself** while building and running this pipeline, see [`../upstream/frama-c-e-acsl-issues.md`](../upstream/frama-c-e-acsl-issues.md).

---

## Target Summary

| Target | Upstream Repository | Evaluated Revision | Confirmed Bugs | Campaign Status | Details |
| :--- | :--- | :--- | :---: | :--- | :--- |
| **minmea** | [`kosma/minmea`](https://github.com/kosma/minmea) | [`c43c9e7`](https://github.com/kosma/minmea/tree/c43c9e7c5ed788122a9d8a5445679e1594f8a030) | **3** (2 Medium, 1 Low) | Complete (`standard` profile) | [`./minmea/README.md`](./minmea/README.md) |
| **QCBOR** | [`laurencelundblade/QCBOR`](https://github.com/laurencelundblade/QCBOR) | [`572a567`](https://github.com/laurencelundblade/QCBOR/tree/572a567d02bcfde42f5863f6a515131cc270798d) (`master`) / [`9bd0845`](https://github.com/laurencelundblade/QCBOR/tree/9bd08456d46ac5fbaa7822420fd3e25e0e9c486f) (`dev`) | **3** (1 Medium, 2 Low) | Complete (`standard` & `deep` profiles) | [`./qcbor/README.md`](./qcbor/README.md) |
| **CryptoLib** | [`nasa/CryptoLib`](https://github.com/nasa/CryptoLib) | [`5b98c8b`](https://github.com/nasa/CryptoLib/tree/5b98c8b2561b22822a9d4e26c959677ed93c815a) | **1** (1 Medium; +1 C11 hygiene note) | Complete (Phase 1–2 + Verification Gate) | [`./cryptolib/README.md`](./cryptolib/README.md) |
| **picohttpparser** | [`h2o/picohttpparser`](https://github.com/h2o/picohttpparser) | [`dd573d8`](https://github.com/h2o/picohttpparser/tree/dd573d8fa9264c646a400e96ce9f07dea6f156e4) | **0** (11 units proven) | Complete (`standard` & `deep` profiles) | [`./picohttpparser/README.md`](./picohttpparser/README.md) |

---

## Master Vulnerability Index

| ID | Target | Title | Location | Property / CWE | Severity | Reachability | Detection Engine | Upstream Ticket | Status |
| :--- | :--- | :--- | :--- | :--- | :---: | :--- | :--- | :--- | :--- |
| [`MINMEA-01`](./minmea/README.md#minmea-01-unvalidated-zda-calendar-fields-cause-signed-integer-overflow-in-minmea_getdatetime) | [`kosma/minmea`](https://github.com/kosma/minmea) | Unvalidated ZDA calendar fields cause signed overflow (`date->month - 1`) in `minmea_getdatetime` | `minmea.c:656` (`minmea_getdatetime`) | `signed_overflow` (CWE-190) | **Medium** | `untrusted_surface` | Phase 1 (`LibFuzzer + UBSan`) | Pending / Not yet filed | Confirmed (Unreported) |
| [`MINMEA-02`](./minmea/README.md#minmea-02-absint_min-signed-overflow-in-minmea_parse_zda-bypasses-utc-offset-validation) | [`kosma/minmea`](https://github.com/kosma/minmea) | `abs(INT_MIN)` signed overflow in `minmea_parse_zda` bypasses UTC timezone-offset range check | `minmea.c:635` (`minmea_parse_zda`) | `signed_overflow` (CWE-190 / CWE-20) | **Medium** | `untrusted_surface` | Phase 1 (`LibFuzzer + UBSan`) | Pending / Not yet filed | Confirmed (Unreported) |
| [`MINMEA-03`](./minmea/README.md#minmea-03-unbounded-scale--10-signed-overflow-in-minmea_scan-fractional-field-parser) | [`kosma/minmea`](https://github.com/kosma/minmea) | Unbounded `scale *= 10` signed overflow in `minmea_scan` fractional (`'f'`) field parser | `minmea.c:186` (`minmea_scan`) | `signed_overflow` (CWE-190) | **Low** | `untrusted_surface` | Phase 1 (`LibFuzzer + UBSan`) | Pending / Not yet filed | Confirmed (Unreported) |
| [`QCBOR-01`](./qcbor/README.md#qcbor-01-c11-signed-integer-overflow-negating-int64_min-in-qcbordecode_processbignumber) | [`laurencelundblade/QCBOR`](https://github.com/laurencelundblade/QCBOR) | C11 signed integer overflow negating `INT64_MIN` in `QCBORDecode_ProcessBigNumber` | `src/qcbor_number_decode.c:1964`, `:2008` (`QCBORDecode_ProcessBigNumber`) | `signed_overflow` (CWE-190) | **Medium** | `untrusted_surface` | Phase 1 (`RTE + E-ACSL + LibFuzzer`) | Pending / Not yet filed | Confirmed (Unreported) |
| [`QCBOR-02`](./qcbor/README.md#qcbor-02-c11-undefined-shift-by-negative-exponent-in-ieee754_doubletosingle) | [`laurencelundblade/QCBOR`](https://github.com/laurencelundblade/QCBOR) | C11 undefined right-shift by negative shift count in `IEEE754_DoubleToSingle` | `src/ieee754.c:666` (`master`) / `src/ieee754.c:625` (`dev`) | `shift` (C11 6.5.7p3 / CWE-758) | **Low** | `internal_api` | Phase 1 (`RTE + E-ACSL + LibFuzzer`) | Pending / Not yet filed | Confirmed (Unreported) |
| [`QCBOR-03`](./qcbor/README.md#qcbor-03-c11-undefined-shift-by-negative-exponent-in-ieee754_singletohalf) | [`laurencelundblade/QCBOR`](https://github.com/laurencelundblade/QCBOR) | C11 undefined right-shift by negative shift count in `IEEE754_SingleToHalf` | `src/ieee754.c:510` (`master`) / `src/ieee754.c:466` (`dev`) | `shift` (C11 6.5.7p3 / CWE-758) | **Low** | `internal_api` | Phase 1 (`RTE + E-ACSL + LibFuzzer`) | Pending / Not yet filed | Confirmed (Unreported) |
| [`CRYPTOLIB-01`](./cryptolib/README.md#cryptolib-01-one-byte-out-of-bounds-read-in-crypto_tc_set_segment_header-on-5-byte-tc-frame) | [`nasa/CryptoLib`](https://github.com/nasa/CryptoLib) | One-byte out-of-bounds read of received TC frame buffer when a minimal 5-byte frame is processed with segmentation headers enabled | `src/core/crypto_tc.c:1949`, `:2025` (`Crypto_TC_Set_Segment_Header`) | `mem_access` (CWE-125) | **Medium** | `untrusted_surface` | Phase 1 (`RTE + E-ACSL + ASan`) | Pending / Not yet filed | Confirmed (Unreported) |

---

## Status Lifecycle

Each finding tracks its disclosure and remediation state using the following statuses:

- **`Confirmed (Unreported)`**: Independently reproduced inside the sandboxed verification pipeline with a verified root cause and candidate patch; ready to be filed upstream.
- **`Reported`**: Upstream GitHub issue or security advisory opened (link recorded in the `Upstream Ticket` column).
- **`Acknowledged`**: Confirmed by upstream maintainers.
- **`Fixed`**: Upstream pull request or commit merged addressing the defect.
- **`Rejected / Won't Fix`**: Upstream maintainers declined the change or documented the behavior as intentional.

---

## Subfolder Structure

Each target subfolder (`./<target>/README.md`) contains public-ready documentation structured for direct copy-paste into upstream GitHub issues:

1. **Target Overview & Verification Summary:** Repository URL, evaluated git commit SHA, pipeline profile, proof coverage statistics, and rejected false positives.
2. **Confirmed Vulnerability Entries:**
   - **Metadata Table:** Bug ID, Fingerprint, Status, Upstream Ticket link, Severity, Reachability, Location (with GitHub commit permalink), and Failing Property.
   - **Summary & Impact:** Clear explanation of how untrusted input reaches the defect and what happens at runtime.
   - **Root Cause Analysis:** Annotated source excerpt pinpointing the exact lines responsible.
   - **Minimal Reproducer:** Hex/ASCII input payload, pipeline replay command, and a standalone C program reproducing the failure under `clang -fsanitize=address,undefined` or `e-acsl-gcc`.
   - **Proposed Fix:** Unified `diff` patch enforcing the required safety invariant.
