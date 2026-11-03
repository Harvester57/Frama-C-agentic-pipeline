# Proving Security Properties Beyond Memory Safety (Layers 1 to 6)

While the `-rte` plugin automatically generates proof obligations for **Layer 1 (Absence of Run-Time Errors / Memory Safety)**, many critical security vulnerabilities in C—such as SNMPv3 authentication bypasses, infinite-loop Denial-of-Service, Syslog CRLF log injection, and cryptographic key leaks—are 100% memory-safe and trigger zero RTE alarms.

This pipeline extends Frama-C verification across **six distinct security layers**, enforced both **statically (`WP` / `Eva`)** and **dynamically (`E-ACSL + LibFuzzer`)**.

---

## Overview of the 6 Security Verification Layers

| Layer | Security Property Class | CWE Mapping | ACSL / Frama-C Mechanism | Template File |
| :---: | :--- | :--- | :--- | :--- |
| **1** | **Memory Safety & AoRTE** (Out-of-bounds read/write, integer overflow, uninitialized read, div-by-zero, null deref) | CWE-119, CWE-125, CWE-190, CWE-457, CWE-787 | `-rte` + `\valid`, `\valid_read`, `\initialized` | Built-in (`-rte`) |
| **2** | **Availability & Anti-DoS** (Guaranteed loop & recursion termination; no zero-advance TLV loops) | CWE-835, CWE-674 | `loop variant`, `decreases` | Built-in (`/framac-wp`) |
| **3** | **Memory Isolation & Sandboxing** (Strict side-effect footprints; parser cannot mutate global auth/config state) | CWE-471, CWE-668 | `assigns`, `loop assigns`, `\separated` | Built-in (`/framac-wp`) |
| **4** | **Authentication & Access-Control State Machines** (No privileged PDU execution without HMAC + VACM pass) | CWE-287, CWE-285, CWE-306 | `/*@ ghost ... */` state variables & transitions | [`layer4_auth_state_machine.acsl`](../templates/acsl/layer4_auth_state_machine.acsl) |
| **5** | **Output Grammar & Sanitization** (No CRLF log injection, delimiter breakout, or NUL truncation) | CWE-93, CWE-117, CWE-74 | Quantified character-class `ensures` predicates | [`layer5_output_sanitization.acsl`](../templates/acsl/layer5_output_sanitization.acsl) |
| **6** | **Confidentiality, Zeroization & Non-Interference** (Key wiping on exit; XML secrets never flow to Syslog) | CWE-226, CWE-532, CWE-200 | `buffer_is_zeroed` + `-eva-domains taint` / `-inout` | [`layer6_zeroization_and_taint.acsl`](../templates/acsl/layer6_zeroization_and_taint.acsl) |

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

A parser function should never be able to overwrite global configuration state or alias its output struct with its input packet buffer.
By requiring `assigns *pdu_out;` and `requires \separated(buf + (0 .. len - 1), pdu_out);` on `snmpv3_parse_pdu()`, WP proves across the entire call tree beneath `snmpv3_parse_pdu()` that **no global variable, static state, or unrelated heap object can be mutated**.

---

## Layer 4: Authentication & Protocol State Machines (`ghost` Variables)

Using [`templates/acsl/layer4_auth_state_machine.acsl`](../templates/acsl/layer4_auth_state_machine.acsl), security state transitions are tracked via ACSL ghost variables (`g_sec_auth_verified` and `g_sec_acl_authorized`), which have **zero runtime cost in production builds** (since they live inside `/*@ ... */` comments) but are:
1. **Compiled into active C assertions during `E-ACSL + LibFuzzer` runs**, turning any authentication bypass path into an immediate `SIGABRT` crash for the fuzzer.
2. **Checked across all control-flow paths by `Frama-C WP`**, proving mathematically that `snmpv3_execute_pdu()` cannot be invoked on an `authPriv` or `authNoPriv` packet unless both `snmpv3_usm_verify_hmac()` and `snmpv3_vacm_check_access()` returned `0` (`SUCCESS`) on the current packet.

---

## Layer 5: Output Grammar & Sanitization Invariants

Using [`templates/acsl/layer5_output_sanitization.acsl`](../templates/acsl/layer5_output_sanitization.acsl), emitters such as Syslog RFC 5424 formatters are annotated with quantified output grammar contracts:
```c
/*@
  requires out_cap > 0 && \valid(out_buf + (0 .. out_cap - 1));
  requires \valid_read(msg + (0 .. msg_len - 1));
  requires \separated(out_buf + (0 .. out_cap - 1), msg + (0 .. msg_len - 1));
  assigns out_buf[0 .. out_cap - 1];
  ensures 0 <= \result < out_cap;
  ensures no_crlf_or_nul(out_buf, \result);
  ensures syslog_sd_value_escaped(out_buf, \result);
*/
size_t syslog_format_sd_param(char *out_buf, size_t out_cap, const char *msg, size_t msg_len);
```
- **In `WP`:** Proves no byte in `out_buf[0 .. \result - 1]` can ever equal `\r`, `\n`, `\0`, or an unescaped `]` / `"`.
- **In `E-ACSL + LibFuzzer`:** The universal quantifier `\forall integer k; 0 <= k < \result` is compiled into a fast bounded C verification loop at function exit, allowing LibFuzzer to hunt for escaping edge cases automatically.

---

## Layer 6: Secret Zeroization & Information Flow (`Taint`)

Using [`templates/acsl/layer6_zeroization_and_taint.acsl`](../templates/acsl/layer6_zeroization_and_taint.acsl):
1. **Zeroization on All Exit Paths:**
   Adding `ensures buffer_is_zeroed(ctx->priv_key, KEY_LEN);` forces WP to verify that even when an early `if (err) return -1;` branch is taken, transient key material is scrubbed before the function returns.
2. **Non-Interference / Taint Tracking (`-eva-domains taint`):**
   Marking sensitive XML configuration fields with `//@ taint cfg->usm_priv_key[0 .. 31];` and asserting `//@ assert !\tainted(syslog_buf[0 .. pkt_len - 1]);` at the Syslog network sink guarantees that secret credentials never leak into diagnostic log packets.
