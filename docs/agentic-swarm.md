# Multi-Agent Swarm Architecture & Dual-Oracle Guardrail

This document explains how the pipeline parallelizes verification across tens or hundreds of subagents when ample compute is available, how the **Dual-Oracle Guardrail** prevents LLM hallucination, and how callers and callees negotiate contracts across topological waves.

---

## 1. Four Levels of Parallelism

### Level 1: Module-Level Parallelism (Phase 1 `/framac-fuzz` & Phase 2 `/framac-eva`)
Independent modules (`snmpv3`, `syslog`, `xml`, `ipc`, etc.) share no internal state during slice verification.
- `/framac-fuzz` and `/framac-eva` spawn **1 subagent per module slice** concurrently.
- Each subagent compiles its own E-ACSL fuzzer binary, runs its own LibFuzzer campaign, and executes its own `frama-c -eva` abstract interpretation pass inside the container.

### Level 2: Speculative Header Decoupling (Stage 3A of `/framac-wp`)
Normally, bottom-up deductive verification must wait for Wave `0` (leaf functions) to finish before Wave `1` (callers) can begin.
- To break this sequential bottleneck, Stage 3A spawns a **Speculative Interface Architect Subagent** per `.h` header file (`skills/framac-wp/header_architect_brief.md`).
- Each Architect writes baseline `requires`, `assigns`, and `ensures` contracts in `workspace/work/<module>.h` and validates them dynamically against the Phase 1 fuzzer corpus using `run_eacsl_fuzz.py guardrail`.
- Because `frama-c -wp -wp-fct <caller>` trusts the `.h` contract of any function `<callee>` it calls, **all functions across the call graph can be verified with minimal cross-wave blocking**.

### Level 3: Topological Wavefront Swarm (Stage 3B of `/framac-wp`)
`build_callgraph_dag.py` partitions all functions in the codebase into bottom-up topological waves:
- **Wave 0 (Leaf Functions — typically ~40% of all C functions):** Call zero other project functions. Every Wave 0 function is 100% independent and can run simultaneously in its own **Function Pod**.
- **Wave 1 .. Wave K:** Proceed bottom-up once their callees' contracts are locked.
- Inside each Function Pod, Frama-C itself dispatches SMT queries across multiple CPU cores via `-wp-par 8` using `Alt-Ergo`, `Z3`, and `CVC5`.

### Level 4: Adversarial Prover-vs-Breaker Dual-Play (Stage 3C of `/framac-wp`)
When a Function Prover Subagent fails to prove a specific RTE or security assertion after `K` retries (default `K = 4`):
- The orchestrator spawns an **Adversarial Breaker Subagent** (`skills/framac-wp/breaker_brief.md`) in parallel.
- While the Prover attempts an alternative loop invariant, the Breaker analyzes the exact unproven assertion and synthesizes surgical binary seed inputs for `E-ACSL + LibFuzzer` to trigger a runtime crash at that line.
- If the Breaker triggers a crash, the Prover is terminated immediately and the bug is recorded with its concrete reproducer.

---

## 2. The Dual-Oracle Anti-Hallucination Guardrail

A fundamental hazard of using LLMs for formal verification is **vacuous truth**: in classical logic, `False ==> Anything` is `Valid`. An unconstrained LLM trying to satisfy `frama-c -wp` might accidentally write an overly restrictive or contradictory precondition such as:
```c
/*@ requires len == 0; */ // Or: requires len < 0 && len > 0;
```
Under that precondition, `frama-c -wp` will report `100% Valid` on every goal inside the function—even if the function contains a blatant buffer overflow when `len > 0`!

### How the Pipeline Prevents Vacuous Contracts

Every single iteration of the Function Prover Subagent (`prover_brief.md`) and Interface Architect Subagent (`header_architect_brief.md`) must pass **two orthogonal oracles** in sequence:

1. **Oracle 1 — The Dynamic E-ACSL Oracle (`run_eacsl_fuzz.py guardrail`):**
   Compiles the newly proposed ACSL annotations (`requires`, `ensures`, `loop invariant`, `assert`) into executable C checks via `e-acsl-gcc` (the same build as Phase 1 fuzzing: instrument with `-n`, full memory tracking, runtime init hook) and replays the module's valid fuzzer corpus (plus 100–200 additional mutations).
   - If *any* real input violates the proposed `requires` or `loop invariant`, the annotation is **immediately rejected as `rejected_overconstrained`**, and the exact failing variable values from the runtime stack trace are fed back to the subagent.
2. **Oracle 2 — The Static Deductive Oracle (`run_wp_function.py`):**
   Only after a contract holds on 100% of real dynamic executions is it passed to `frama-c -wp -wp-rte -wp-fct <fn>` to prove that it holds mathematically across *all* possible inputs.

---

## 3. Cross-Wave Caller-Callee Contract Negotiation

When Caller Function `B` (in Wave `W`) calls Callee Function `A` (in Wave `W-1`), `B`'s WP proof may fail because `A`'s `.h` header contract only states:
```c
/*@ ensures \result >= -1; */
int parse_ber_length(const uint8_t *buf, size_t max_len);
```
whereas Caller `B` needs to know that `\result <= (int)max_len` to prove that advancing `buf + \result` stays in bounds.

Instead of allowing Caller Subagent `B` to edit Callee `A`'s contract directly (which could break `A`'s proof or cause race conditions between parallel subagents), `B` invokes [`scripts/contract_negotiator.py`](file:///C:/Users/Florian/OneDrive/Documents/Dev/frama-c/scripts/contract_negotiator.py):

```bash
python3 /opt/framac-pipeline/scripts/contract_negotiator.py request \
  --caller snmpv3_parse_pdu \
  --callee parse_ber_length \
  --callee-file src/snmp/ber_decode.c \
  --header-file include/ber_decode.h \
  --needed-clause "ensures \result <= (int)max_len;" \
  --reason "Required by snmpv3_parse_pdu to prove \valid_read(buf + offset + \result)"
```

At the wave boundary:
1. The orchestrator dispatches Callee Subagent `A` to evaluate the requested `ensures \result <= (int)max_len;` clause.
2. Subagent `A` tests the stronger clause against **Oracle 1 (`E-ACSL guardrail`)** and **Oracle 2 (`WP` on `parse_ber_length`)**.
3. **Outcome 1 (True in `A`):** Both oracles pass. Subagent `A` commits the stronger `ensures` clause to `include/ber_decode.h` and marks the request `verified_and_applied`. Caller `B`'s proof now succeeds automatically.
4. **Outcome 2 (False in `A`):** `parse_ber_length` does *not* actually enforce `\result <= max_len`! That immediately reveals either a missing bounds check inside `parse_ber_length` or a missing bounds check in `snmpv3_parse_pdu`.
