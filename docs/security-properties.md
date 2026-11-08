# Proving Security Properties Beyond Memory Safety (Layers 1 to 6)

While the `-rte` plugin automatically generates proof obligations for **Layer 1 (Absence of Run-Time Errors / Memory Safety)**, many critical security vulnerabilities in C—such as SNMPv3 authentication bypasses, infinite-loop Denial-of-Service, Syslog CRLF log injection, and cryptographic key leaks—are 100% memory-safe and trigger zero RTE alarms.

This pipeline extends Frama-C verification across **six distinct security layers**. Layers 1 and 2 are checked statically (`Eva`, `WP`) and dynamically (`E-ACSL + LibFuzzer`); Layers 3 to 6 are proved by `WP`.

---

## Overview of the 6 Security Verification Layers

| Layer | Security Property Class | CWE Mapping | ACSL / Frama-C Mechanism | Source |
| :---: | :--- | :--- | :--- | :--- |
| **1** | **Memory Safety & AoRTE** (Out-of-bounds read/write, integer overflow, uninitialized read, div-by-zero, null deref) | CWE-119, CWE-125, CWE-190, CWE-457, CWE-787 | `-rte` + `\valid`, `\valid_read`, `\initialized` | Built-in (`-rte`) |
| **2** | **Availability & Anti-DoS** (Guaranteed loop & recursion termination; no zero-advance TLV loops) | CWE-835, CWE-674 | `loop variant`, `decreases` | Built-in (`/framac-wp`) |
| **3** | **Memory Isolation** (every function writing through a pointer has a proven frame) | CWE-471, CWE-668 | `assigns`, `loop assigns`, `\separated` | `scripts/security_props.py` (class `l3_frame`) |
| **4** | **Authentication gates** (only the gate writes the auth state; privileged functions require it) | CWE-287, CWE-285, CWE-306 | MetAcsl `\writing` and `\precond` meta-properties | threat model `auth_gates`, [`templates/metacsl/l4_*.acsl`](../templates/metacsl/) |
| **5** | **Output sanitization** (no CR/LF reaches a log or terminal sink; no uninitialized byte reaches any sink) | CWE-93, CWE-117, CWE-457, CWE-200 | MetAcsl `\calling` (writers) or `\postcond` (buffer sinks) | threat model `output_sinks`, [`templates/metacsl/l5_sanitized.acsl`](../templates/metacsl/l5_sanitized.acsl) |
| **6** | **Secrets** (wiped when released; never handed to or read by an output sink) | CWE-226, CWE-532, CWE-200 | MetAcsl `\postcond`, `\calling` and `\reading` | threat model `secrets`, [`templates/metacsl/l6_*.acsl`](../templates/metacsl/) |

Layers 3 to 6 come from what the structured threat model (the `framac-threat-model` block of `THREAT_MODEL.md`, `schemas/threat_model.schema.json`) requires, not from patterns in the code (plan step I9). The old per-function pattern matching and its ACSL templates for Layers 4 to 6 are gone.

How it runs:

1. `/framac-slice` Step 3 runs `scripts/security_props.py run`. It reads the Phase 0 model (`workspace/reports/phase0_model.json`) and the threat model, and writes `workspace/reports/security_props.json`.
2. Each property is rendered from [`templates/metacsl/`](../templates/metacsl/) as a MetAcsl meta-property, and lists its `instances`: the functions where its generated annotations land. Those are the ledger units (`l3_frame`, `l4_auth_state`, `l4_auth_required`, `l5_sanitized`, `l6_wiped`, `l6_no_leak`), seeded by `ledger.py seed`.
3. `run_wp_function.py` loads the properties of the function under proof (`--security-props`, default the run's file; `none` turns it off) and runs `-meta -then-last -wp`. A prover discharges the generated `assert`, `requires` and `ensures` named `<property>: meta:` like any other goal, and the prover brief lists what to discharge.

Without a threat model only Layer 3 is generated.

A threat model block looks like this (fields per kind: `input_sources` `function`, `role`, `params`; `trusted_callers` `unit`, `except`, `functions`, `reason`; `secrets` `name`, `kind`, `function`, `size`, `object`; `auth_gates` `function`, `state`, `protects`; `output_sinks` `function`, `kind`, `params`, `length`):

````markdown
```json framac-threat-model
{
  "schema_version": 1,
  "target": "example",
  "input_sources": [{"function": "parse_packet", "role": "entry", "description": "Bytes from the network."}],
  "trusted_callers": [],
  "secrets": [{"name": "session_key", "kind": "global", "function": "session_close", "description": "Session key."}],
  "auth_gates": [{"function": "login", "state": "auth_ok", "protects": ["admin"], "description": "Password check."}],
  "output_sinks": [{"function": "syslog", "kind": "log", "description": "System log."}]
}
```
````

`python3 /opt/framac-pipeline/scripts/trust.py check-threat-model [PATH]` validates it and checks its names against the model.

---

## Layer 2: Termination & Anti-DoS (`loop variant`)

In binary protocol parsers (like ASN.1/BER in SNMPv3), a crafted length field (`len == 0`) can cause a `while (offset < total_len)` loop to advance by `0` bytes per iteration, freezing the daemon via a single UDP packet.

Every loop verified by `/framac-wp` must include a `loop variant` expression:
```c
/*@
  loop invariant 0 <= offset <= total_len;
  loop assigns offset, pdu_out->field_count;
  loop variant total_len - offset;
*/
while (offset < total_len) {
    size_t consumed = ber_decode_element(buf + offset, total_len - offset, pdu_out);
    if (consumed == 0) {
        return -1; // Required! Without this check, WP fails to prove `total_len - offset` strictly decreases!
    }
    offset += consumed;
}
```
If `ber_decode_element` can return `0` and the caller forgets `if (consumed == 0) return -1;`, **Frama-C WP immediately fails the `loop_variant_positive` / `loop_variant_decreases` goal**, exposing the infinite-loop DoS statically.

---

## Layer 3: Strict Memory Isolation (`assigns` & `\separated`)

Every function that writes through a pointer (the Phase 0 dump records the writes, and a call to a libc writer such as `memcpy` counts) gets an `l3_frame` unit: its contract needs an `assigns` clause naming exactly what it writes, which WP proves. A parser with `assigns *pdu_out;` and `requires \separated(buf + (0 .. len - 1), pdu_out);` cannot mutate global configuration state or alias its output with its input.

---

## Layer 4: Authentication Gates

An auth gate `{"function": "login", "state": "auth_ok", "protects": ["admin"]}` becomes two meta-properties:

```c
/*@ meta \prop, \name(L4_auth_state_login), \targets(\diff(\ALL, {login})), \context(\writing),
      \separated(\written, &auth_ok);
    meta \prop, \name(L4_auth_required_login), \targets({admin}), \context(\precond),
      auth_ok != 0;
*/
```

MetAcsl puts an assertion before every write of every other function (a write of `auth_ok` outside the gate becomes `\false`), and a `requires` on `admin` that WP proves at each call site. A state that hangs off a parameter (`ctx->authed`) is checked in the functions that have that parameter.

---

## Layer 5: Output Sanitization

An output sink is checked where data reaches it. For a `log` or `terminal` sink, each text parameter must hold no CR or LF before its terminating NUL (`L5_no_crlf`, log injection); for the other kinds, every byte handed over must be initialized (with the sink's `length` parameter, else the object pointed to). These are `\calling` properties, so they also hold for a sink the target only declares (`syslog`, `send`). A `buffer` sink (the output is returned in an out-parameter, like `QCBOREncode_Finish`) gets a postcondition: its out-parameters are initialized when it returns.

Output grammars specific to a format (RFC 5424 structured-data escaping, delimiter breakout) are not generated: a prover adds them as named `L5_*` clauses where the threat model calls for them.

---

## Layer 6: Secrets

A secret `{"name": "session_key", "kind": "global", "function": "session_close"}` becomes:

1. **`L6_wiped_session_key`:** a postcondition of the release function: every element is zero when it returns, on every path (`size` sets the element count of a pointer secret; arrays default to `sizeof`). WP proves a wipe written as a loop with invariants; a `memset` of an `unsigned char` array does not prove under WP's Typed model. WP also cannot see a wipe the compiler drops as a dead store, so the production code should use `explicit_bzero` or a volatile write.
2. **`L6_no_leak_session_key`:** at every call of an output sink, no argument points into the secret (`\calling`), and a sink the target defines never reads it (`\reading`).

The no-leak check sees direct flows only. A copy of the secret into a buffer that later reaches a sink needs Eva's taint domain (`-eva-domains taint`, `//@ taint ...;` at the source and `//@ assert !\tainted(...);` at the sink, or the upstream `__fc_private` / `security_status` idiom vendored in `docs/upstream/sources/`), which the pipeline does not generate.

---

## Known Limits

- **Pipeline integration:** `security_props.py run` is a `/framac-slice` step. The benchmark and the generated Makefile do not run it.
- **L3 over-approximation:** a call to a libc memory writer counts as a pointer write even when its destination is local.
- **L5 on string literals:** `L5_no_crlf` on a literal argument does not prove, even with Alt-Ergo, Z3 and CVC5 at 10 s.
- **Wipes under the Typed model:** a `memset` of an `unsigned char` array does not prove; a loop with invariants does.
- **Returned secrets:** a secret of kind `return` gives a warning and no property.
