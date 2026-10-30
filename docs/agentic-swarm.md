# Multi-Agent Swarm Architecture & Dual-Oracle Guardrail

This document explains:
- how the pipeline parallelizes verification across as many subagents and tool processes as the machine allows;
- how the **Dual-Oracle Guardrail** prevents LLM hallucination;
- how callers and callees negotiate contracts.

How resources are measured, leased and cached is in [`resources-and-caching.md`](resources-and-caching.md).

---

## 1. Levels of Parallelism

Concurrency is never a fixed number:
- The host broker leases CPUs and memory to every container from the measured pool.
- Each tool sizes itself from its lease.
- The scheduler hands out as many agent tasks as `resources.py recommend` allows, recomputed every round.

LLM subagents are used only where judgment is needed.

### Level 1: Module-Level Parallelism without Subagents (Phase 1 `/framac-fuzz` & Phase 2 `/framac-eva`)
Independent modules (`snmpv3`, `syslog`, `xml`, `ipc`, etc.) share no internal state during slice verification, and their fuzz and Eva runs need no reasoning.
- A generated Makefile (`pipeline_make.py`) runs them. Each recipe is admitted by CPU and memory inside one container per phase.
- Fuzzing (CPU-bound) and Eva (single-threaded, memory-bound) run **at the same time**, as two background phases. Ingestion keeps the fuzz-then-Eva order.
- Each campaign runs as many LibFuzzer workers as its lease allows. Builds and Eva results are cached by content, so a harness repair re-runs only what changed.

### Level 2: Speculative Header Decoupling (architects)
Bottom-up verification would otherwise have to wait for leaf functions before callers.
- A **Speculative Interface Architect Subagent** per `.h` header (`skills/framac-wp/header_architect_brief.md`) writes baseline `requires`, `assigns`, and `ensures` contracts.
- It validates them dynamically against the Phase 1 fuzzer corpus using `run_eacsl_fuzz.py guardrail`.
- Because `frama-c -wp -wp-fct <caller>` trusts the `.h` contract of any function `<callee>` it calls, a caller only waits for its callees' own provers, never for a global wave.

### Level 3: Dependency-Driven Function Provers (no waves)
`wp_scheduler.py` keeps a ready queue instead of global waves. A function's prover is dispatched as soon as all of these are done:
- its callees are merged (recursion cycles become ready together);
- the architects of its own module and of every callee's module;
- the gate of every fuzz/Eva slice covering its file.

Ordering and merging:
- Functions with the longest chains of callers waiting on them go first, so the critical path starts early.
- Inside each prover's WP run, `-wp-par` follows the lease (min of CPUs and memory at the fixed 1000 MB prover limit).
- Finished provers are merged in micro-batches. Their parent re-checks run in parallel, one WP job per function.

### Level 4: Adversarial Prover-vs-Breaker Dual-Play
When a Function Prover Subagent fails to prove a specific RTE or security assertion after `K` retries (default `K = 4`):
- The scheduler queues an **Adversarial Breaker Subagent** (`skills/framac-wp/breaker_brief.md`). Callers of the stalled function are released immediately: the breaker never blocks them.
- The Breaker analyzes the exact unproven assertion and synthesizes surgical binary seed inputs for `E-ACSL + LibFuzzer` to trigger a runtime crash at that line.
- A crash becomes a candidate for an independent Crash Verifier. It reopens the gates of the slices it affects, so no further proof work starts on code that may be broken.

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

## 3. Caller-Callee Contract Negotiation

When Caller Function `B` calls Callee Function `A`, `B`'s WP proof may fail because `A`'s `.h` header contract only states:
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

As soon as the request is ingested (`wp_scheduler.py complete`), the scheduler emits a `negotiate` task for `A`. Requests are capped per caller/callee pair, and `B` is requeued once the request is resolved:
1. The orchestrator dispatches Callee Subagent `A` to evaluate the requested `ensures \result <= (int)max_len;` clause.
2. Subagent `A` tests the stronger clause against **Oracle 1 (`E-ACSL guardrail`)** and **Oracle 2 (`WP` on `parse_ber_length`)**.
3. **Outcome 1 (True in `A`):** Both oracles pass. Subagent `A` commits the stronger `ensures` clause to `include/ber_decode.h` and marks the request `verified_and_applied`. Caller `B`'s proof now succeeds automatically.
4. **Outcome 2 (False in `A`):** `parse_ber_length` does *not* actually enforce `\result <= max_len`! That immediately reveals either a missing bounds check inside `parse_ber_length` or a missing bounds check in `snmpv3_parse_pdu`.
