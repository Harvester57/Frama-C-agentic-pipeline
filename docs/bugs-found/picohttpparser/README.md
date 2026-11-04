# Verification Results for `picohttpparser` (`h2o/picohttpparser`)

- **Master Index:** [`../README.md`](../README.md)
- **Upstream Repository:** [https://github.com/h2o/picohttpparser](https://github.com/h2o/picohttpparser)
- **Evaluated Revision:** [`dd573d8fa9264c646a400e96ce9f07dea6f156e4`](https://github.com/h2o/picohttpparser/tree/dd573d8fa9264c646a400e96ce9f07dea6f156e4)
- **Scope:** `picohttpparser.c`, `picohttpparser.h`
- **Pipeline Profiles Run:** `standard` (`run-1`) and `deep` (`run-2`)

---

## Summary of Findings

- **Confirmed Findings:** **0**
- **Needs Validation:** **0**
- **Rejected Candidates:** **1** (`disproved_by_source` — prover hypothesis on C11 unsigned modulo narrowing)

---

## Assurance & Proof Highlights

While no bugs were found in `picohttpparser`, the pipeline's formal verification stages (`Eva` and `WP`) and `RTE + E-ACSL + LibFuzzer` campaigns established the following guarantees:

1. **Covered Obligation Units (11 units across `rte` and `l2_termination`):**
   - `decode_hex` (proven via WP)
   - `findchar_fast` (proven via WP)
   - `is_complete` (proven via WP)
   - `parse_http_version` (proven via WP)
   - `parse_token` (proven via WP)
   - `get_token_to_eol` (`65 / 65` VCs proven in `run-2` using pointer-anchor loop invariants)
2. **High-Complexity Functions (Partial VC Discharge):**
   - `parse_headers`: `696 / 718` VCs (`96.9%`) discharged by WP after merging the `get_token_to_eol` contract.
   - `phr_decode_chunked`: `3,134 / 3,151` VCs (`99.5%`) discharged by WP with `0` solver failures (remaining `17` VCs are solver capacity timeouts on `memmove` context preservation).
