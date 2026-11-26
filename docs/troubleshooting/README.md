# Troubleshooting Guide

Common issues encountered when running Frama-C (`RTE`, `Eva`, `WP`, `E-ACSL`), `MetAcsl`, and Clang LibFuzzer on real-world C codebases, and how to resolve them.

If a symptom is not listed in the thematic guides below, look it up in the upstream manuals in [`../references/README.md`](../references/README.md). Grep [`../references/INDEX.md`](../references/INDEX.md) or the manual itself, then read only the matching lines.

> [!IMPORTANT]
> **Updating this folder:** Whenever you encounter a pipeline bug, gap, or workaround while running or developing the pipeline, record it in the appropriate thematic file in the same session. Read [`./AGENTS.md`](./AGENTS.md) for the routing rules, required entry format, link depth (`../../` for repo-root paths, `../` for sibling `docs/` files), and validation checks.

---

## Thematic Sub-Documents

| Theme | Sub-Document | Scope & Key Topics |
| :--- | :--- | :--- |
| **Toolchain & Upgrade Notes** | [`./toolchain-upgrades.md`](./toolchain-upgrades.md) | Frama-C 34 (Selenium) and 35.0~~dev (Bromine) behavior changes, ACSL clause ordering, array-to-pointer decay, `-rte-initialized` hooks, machine modes, and base-image bump checks. |
| **Build Capture, Model & Threat Model** | [`./phase0-build-and-model.md`](./phase0-build-and-model.md) | `needs_build_recipe`, `unsupported_architecture`, `bear` parallel build timeouts, Windows CRLF checkouts, `gcc_fallback`, `phase0_dump.ml`, `THREAT_MODEL.md` parsing, compiler variants, and product vs. test unit classification. |
| **Harnesses, Reach Gates & Seeds** | [`./harnesses-and-seeds.md`](./harnesses-and-seeds.md) | `--api` and `argv` harness generation, auto-prelude header ordering, opaque handles & lifecycle cases, `harness_reach.py` static and dynamic reach gates, `build-check`, `llvm-cov` coverage builds, and `seed_harvest.py` / `fuzz_assets.py`. |
| **Kernel Parsing, Preprocessing & Stubs** | [`./kernel-and-stubs.md`](./kernel-and-stubs.md) | `__fc_libc` gaps (`fd_set`, `ip_mreq`, `sin_zero`, `ioctl`, `syscall`, `<netinet/ip_icmp.h>`, `<bsd/string.h>`), `fc_cpp_wrapper.py` (`offsetof`), ACSL string vocabulary, `stub_check.py` ABI/Eva/dynamic checks, and `libc_gap_report.py`. |
| **E-ACSL & LibFuzzer** | [`./eacsl-and-fuzzing.md`](./eacsl-and-fuzzing.md) | `e-acsl-gcc` two-stage builds, shadow memory (`LLVMFuzzerInitialize`, ASan conflicts, `errno` shim), `\initialized` on formals and `__retres`, guarded/unbounded quantifiers, uninstrumented library pointers, variadic fallbacks, and sanitizer crash parsing/fingerprinting. |
| **Eva Abstract Interpretation** | [`./eva.md`](./eva.md) | High `Unknown` alarm counts, `eva-tune` precision ladder, flamegraphs & `-nonterm`, input buffer initialization (`FRAMAC_FUZZ_COPY`), global initializer null-offset idioms, loop unroll annotations, and `repair_hints`. |
| **WP Deductive Verification & Guardrail** | [`./wp-and-guardrail.md`](./wp-and-guardrail.md) | Quick WP symptom-to-fix table, loop invariants & `assigns`, `Typed` memory-model cast limits, vacuity smoke tests, E-ACSL `<==>` guardrail rewrites, crashes outside checked functions, prover scope checks, contract negotiation, `spec_kb`, `mutation_check.py`, and `proof_carry.py`. |
| **Security Properties (Layers 4–6)** | [`./security-properties.md`](./security-properties.md) | MetAcsl static simplification (`wp_no_credited_goals`), L4 auth gate failure checks, L5 literal CR/LF decisions and format-string checks (`CWE-134`), L6 secret wiping (`explicit_bzero`/`memset_s`, local buffers) and `--eva-taint` copy tracking. |
| **Ledger, Verifier & Artifacts** | [`./ledger-and-verifier.md`](./ledger-and-verifier.md) | Schema validation (`function_id`, `coverage-ledger.json`, `findings.schema.json`), `scaffold-verifier` and `ingest-verifier` (`linked_units`, `deferred` units), `unresolved` deduplication, and candidate reopening after re-fuzzing. |
| **Resources, Caches & Host Tooling** | [`./resources-and-infra.md`](./resources-and-infra.md) | Resource broker leases and static command allowlists, per-module stub cache keys, `loop_seeds.py` sizing and `no_harm` checks, `pipeline.mk` staging, `patterns.py`, PowerShell flag quoting, Windows skill mirror sync, and Cygwin fork failures. |

### Resolved & Archived Entries

[`./resolved.md`](./resolved.md) holds the entries moved out of the guides above because nothing in them is still actionable: the pipeline defect is fixed on `main`, what they describe no longer exists, or the one-off workaround is no longer needed. They are kept verbatim, grouped by the guide they came from, each with an `Archived` bullet giving the date and reason. Search it when an old error message is not in the thematic guides.

---

## Quick Lookup Commands

Search across all troubleshooting documents at once from the repository root:

```powershell
# Windows (PowerShell)
git grep -n -i "<error text or script>" docs/troubleshooting/
```

```bash
# Linux / macOS
git grep -n -i "<error text or script>" docs/troubleshooting/
```

List all currently open pipeline bugs recorded across the guides (no archived entry matches):

```powershell
git grep -n -i "open pipeline" docs/troubleshooting/
```
