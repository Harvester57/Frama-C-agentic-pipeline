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
| **4** | **Authentication gates** (only the gate writes the auth state; privileged functions require it) | CWE-287, CWE-285, CWE-306 | MetAcsl `\writing` and `\precond` meta-properties | threat model `auth_gates`, [`templates/metacsl/l4_*.acsl`](../../templates/metacsl/) |
| **5** | **Output sanitization** (no CR/LF reaches a log or terminal sink; a format argument is a string literal; no uninitialized byte reaches any sink) | CWE-93, CWE-117, CWE-134, CWE-457, CWE-200 | MetAcsl `\calling` (writers), `\precond` (a sink called through a function pointer) or `\postcond` (buffer sinks) | threat model `output_sinks`, [`templates/metacsl/l5_sanitized.acsl`](../../templates/metacsl/l5_sanitized.acsl) |
| **6** | **Secrets** (wiped when released; never handed to or read by an output sink) | CWE-226, CWE-532, CWE-200 | MetAcsl `\postcond`, `\calling` and `\reading` | threat model `secrets`, [`templates/metacsl/l6_*.acsl`](../../templates/metacsl/) |

Layers 3 to 6 come from what the structured threat model (the `framac-threat-model` block of `THREAT_MODEL.md`, `schemas/threat_model.schema.json`) requires, not from patterns in the code (plan step I9). The old per-function pattern matching and its ACSL templates for Layers 4 to 6 are gone.

How it runs:

1. `/framac-slice` Step 3 runs `scripts/security_props.py run`. It reads the Phase 0 model (`workspace/reports/phase0_model.json`) and the threat model, and writes `workspace/reports/security_props.json`.
2. Each property is rendered from [`templates/metacsl/`](../../templates/metacsl/) as a MetAcsl meta-property, and lists its `instances`: the functions where its generated annotations land. Those are the ledger units (`l3_frame`, `l4_auth_state`, `l4_auth_required`, `l5_sanitized`, `l6_wiped`, `l6_no_leak`), seeded by `ledger.py seed`.
3. `run_wp_function.py` loads the properties of the function under proof (`--security-props`, default the run's file; `none` turns it off) and runs `-meta -then-last -wp`. A prover discharges the generated `assert`, `requires` and `ensures` named `<property>: meta:` like any other goal, and the prover brief lists what to discharge.

Without a threat model only Layer 3 is generated.

### Other engines: `meta_engines` and the module meta file

WP is the only engine that checks the properties today. Two pieces are in place for Eva and E-ACSL to check them on a whole module ([`../plans/metacsl-exploitation-plan.md`](../plans/metacsl-exploitation-plan.md), section 3; the runners that use them are packages B and C of that plan):

- **The switch.** `security_props.json` has `meta_engines`, a list within `eva` and `eacsl`. `security_props.py run --meta-engines eva,eacsl` sets it, `--meta-engines none` clears it, and a plain run keeps the previous choice, so the Makefile's `security-props` target does not undo it. `security_props.meta_engines(props)` reads it. Absent or empty means WP only, which is the default.
- **The module meta file.** `security_props.module_meta_file_text(props, functions=None)` returns `(text, names, sources)`, or `None` when there is nothing to load: the meta file of a whole-module run, where MetAcsl instantiates each property in every function of the parse. `functions` is a list of `file#name` ids and selects the properties with an instance among them; `None` selects every property with an instance. A property without instances (decided from the model, or a forwarding sink) and a property written into the work tree (`code`) are left out. The layout is the one of a function's meta file (`meta_file_text`), so `security_props.meta_line_names(text)` maps the line of a report row back to its property.

A threat model block looks like this (fields per kind: `input_sources` `function`, `role`, `params`; `trusted_callers` `unit`, `except`, `functions`, `reason`; `secrets` `name`, `kind` (`global`, `parameter`, `field`, `local`, `return`), `function`, `size`, `object`; `auth_gates` `function`, `state`, `protects`, `success`; `output_sinks` `function`, `kind`, `params`, `length`, `format`):

````markdown
```json framac-threat-model
{
  "schema_version": 1,
  "target": "example",
  "input_sources": [{"function": "parse_packet", "role": "entry", "description": "Bytes from the network."}],
  "trusted_callers": [],
  "secrets": [{"name": "session_key", "kind": "global", "function": "session_close", "description": "Session key."}],
  "auth_gates": [{"function": "login", "state": "auth_ok", "protects": ["admin"], "success": "0", "description": "Password check."}],
  "output_sinks": [{"function": "syslog", "kind": "log", "params": ["param1"], "format": "param1", "description": "System log."}]
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

Neither property stops the gate itself from setting the state on a failed check. With the gate's `success` value (`"success": "0"`, a C constant expression, plan step M7), a third property, `L4_auth_state_login_on_failure`, says that any other result leaves the state as it was on entry. MetAcsl's `\postcond` context cannot name `\result`, so `security_props.py run` writes it into the work tree, on the same line, before each `return` of the gate, with the returned expression in place of the result:

```c
if (pw != 42)
    /*@ check L4_auth_state_login_on_failure: (-1) != (0) ==> auth_ok == \at(auth_ok, Pre); */ return -1;
```

WP proves it with the gate (unit `l4_auth_state` of the gate, which the other two properties never name); E-ACSL executes it as a non-blocking `check`. A `return` whose expression the check cannot repeat (a call, an assignment) or a `return;` is skipped and listed in the warnings: store the result in a local first.

---

## Layer 5: Output Sanitization

An output sink is checked where data reaches it. For a `log` or `terminal` sink, each text parameter must hold no CR or LF before its terminating NUL (`no_crlf_string`, log injection); for the other kinds, every byte handed over must be initialized (with the sink's `length` parameter, else the object pointed to). These are `\calling` properties, so they also hold for a sink the target only declares (`syslog`, `send`). A caller that hands a text sink string literals only gets no goal: the provers do not discharge `no_crlf_string` on a literal, so `security_props.py` decides it from the model, which records the literal each call passes (`call_sites`): satisfied when no literal holds CR or LF before its NUL, else violated. The property lists it under `decided`, and the ledger seed records the verdict (a `covered` unit with evidence of phase `static`, or a `blocked` one). A `buffer` sink (the output is returned in an out-parameter, like `QCBOREncode_Finish`) gets a postcondition: its out-parameters are initialized when it returns.

**A sink called through a function pointer.** At an indirect call MetAcsl has no callee to read the formals from (`[meta] Warning: \called_arg cannot be used with indirect calls`): the `\fguard` turns the clause into `\false`, and the generated assertion reads `!(pointer == &sink)`, which never proves where the pointer may hold the sink. A sink the target defines that the model shows called through a pointer (an `indirect` edge: a call site's type match, or its address handed to an external) therefore gets the same obligation as its precondition:

```c
/*@ meta \prop, \name(L5_sanitized_tcp_send), \targets({tcp_send}), \context(\precond),
      \fguard(\initialized(\formal(req) + (0 .. \formal(req_length) - 1)));
*/
```

WP proves the generated `requires` at each call of the sink, so the instances are still its callers. A call through a pointer needs `/*@ calls tcp_send; */`, as every pointer call does under WP; without it the run is flagged unsound, no goal carries the property, and the ledger credits nothing.

**Forwarding sinks.** A threat model often lists both a wrapper and the function that transmits (libmodbus: `send_msg` and `_modbus_tcp_send`). The callers of the wrapper may hand it a buffer that the wrapper, or a hook it calls, completes before anything is sent (the two MBAP length bytes). A check at the wrapper's calls then demands more than the sink needs and is false on correct code. So a bytes sink (every kind but `log`, `terminal` and `buffer`) that the target defines and that reaches another declared bytes sink in the Phase 0 model's call graph (direct and indirect edges) is a forwarding sink:

- its property has no instance and no MetAcsl text, and lists the innermost declared sinks under `forwarded_to`, with a note;
- the bytes are checked at the calls of those sinks, where they leave, after whatever was completed on the way;
- the callers of the wrapper get no `l5_sanitized` unit. What the wrapper needs from them is its ordinary contract.

This rests on one argument: bytes leave the target only through the declared sinks, and on every path the model finds from the wrapper the first declared sink is checked at its own call. Its limits:

- **An undeclared backend.** When one indirect call site on the way may reach a declared sink and also a function that reaches none (a backend table with a declared TCP `send` and an undeclared RTU one), forwarding would stop checking what the second transmits. The wrapper keeps its property at its callers and `security_props.json` warns, naming the call site and the function: declare that function, or what it transmits through, as an output sink. The model's type match ignores `const`, so a candidate counts only when its parameters have the kinds of a candidate that reaches a sink (the backend's `recv` does not stop a `send` site), or when the model does not know them.
- **A wrapper that also transmits by itself** through a function the threat model does not declare, on a direct call (`write`), is not seen. The threat model must list every function the bytes leave through.
- **The reach is the model's.** A pointer call resolved by type that never happens at run time still counts as a path to a sink.
- **Text sinks keep their placement:** a wrapper does not sanitize, its callers must.
- Two sinks that only reach each other keep one property between them.

A sink with a `format` parameter (`{"function": "syslog", "kind": "log", "format": "param1", ...}`, CWE-134; Frama-C's libc declares `syslog(int, const char *, ...)` without parameter names, so the kernel calls them `param0`, `param1`, ...: name a parameter of such a prototype by its 0-based position, here and in `params`) gets `L5_sanitized_format_<sink>`: the argument there is a string literal at every call. It is decided from the model like the literals above, never by WP: a caller whose every call passes a literal format is `satisfied`, one with any other format is `violated` (the ledger seed blocks its `l5_sanitized` unit). A caller that is a format sink of the threat model itself forwards its own format, so its callers are checked instead; declare such wrappers. A model without call sites decides nothing and says so in a warning.

The properties name the canonical vocabulary of `templates/acsl/acsl_vocabulary.h` (plan step S8) and define no predicate of their own: `no_crlf_string(s)` (a NUL-terminated string, bounded by `strlen`) and, for a length-bounded buffer, `no_crlf_or_nul(buf, len)`. The meta file does not include the vocabulary header, so its preamble takes `strlen` from `__fc_string_axiomatic.h` and repeats `no_crlf_string` with the vocabulary's exact text (Frama-C merges identical definitions; `test_preamble_repeats_the_vocabulary_text` keeps the two equal). The MetAcsl properties only reach WP; E-ACSL can execute `no_crlf_string` through `strlen` where a contract names it.

Output grammars specific to a format (RFC 5424 structured-data escaping, delimiter breakout) are not generated: a prover adds them as named `L5_*` clauses where the threat model calls for them.

---

## Layer 6: Secrets

A secret `{"name": "session_key", "kind": "global", "function": "session_close"}` becomes:

1. **`L6_wiped_session_key`:** a postcondition of the release function: every element is zero when it returns, on every path (`size` sets the element count of a pointer secret; arrays default to `sizeof`). WP proves a wipe written as a loop with invariants; a `memset` of an `unsigned char` array does not prove under WP's Typed model. `explicit_bzero` and `memset_s` carry contracts in `templates/fc_stubs/fc_compat_types.h` whose postconditions state every zeroed element: a wipe through them proves under Typed for a `char` array, and for an `unsigned char` or `uint8_t` array only under `Typed+cast`, which the pipeline does not credit (Typed rejects the array's conversion to `void *`). WP also cannot see a wipe the compiler drops as a dead store, so the production code should use `explicit_bzero` or a volatile write.

   A secret held in a local array (`{"name": "buf", "kind": "local", "function": "derive", "size": "16"}`; `size` defaults to `sizeof` of the array, a pointer local needs it) cannot be named by a postcondition. `security_props.py run` writes `/*@ check L6_wiped_buf: \forall integer i; 0 <= i < sizeof(buf) / sizeof(buf[0]) ==> buf[i] == 0; */` into the work tree, on the same line, before each `return` in the local's scope (from its declaration, the first use of the name in the body, to the end of its block) and before that block's closing brace. The property has a `code` field and no meta-file text; `security_props.json` lists the placed checks under `code_checks`, and a re-run rewrites them. WP proves the check with the function (unit `l6_wiped` of the owning function). E-ACSL executes it as a `check`: a failure is printed and the run goes on, so a fuzz campaign is not stopped by it. A local secret gets no no-leak property.
2. **`L6_no_leak_session_key`:** at every call of an output sink, no argument points into the secret (`\calling`), and a sink the target defines never reads it (`\reading`).

The no-leak check sees direct flows only. A copy of the secret into a buffer that later reaches a sink is Eva's taint domain's job. `security_props.py run --eva-taint` (opt-in; the choice is kept in `security_props.json`, so the Makefile's plain `security-props` run keeps it, and `--no-eva-taint` removes the annotations again) writes, from each no-leak property's `taint` plan, ACSL comments into the work tree on the lines they belong to (no line number moves):

- `/*@ taint <secret>; */` where the secret gets its value: at the entry of the function holding a parameter or field secret; for a global one, before each `return` (and the closing brace) of the functions that write it directly or call a libc memory writer.
- `/*@ assert L6_no_leak_<secret>: eva_taint: !\tainted(<region>); */` before each sink call in the property's calling instances: the pointed-to region (`[0 .. length - 1]` with the sink's `length` parameter, else the first byte). The second name, `eva_taint`, lets a WP run leave the check out. A call the assertion cannot precede (inside a condition or an expression) or whose argument it cannot repeat (a call, an assignment) is listed under `eva_taint.skipped`.

It sets `eva_taint` in `params.json` (`EVA_TAINT_<mod>`, `taint` added to Eva's domains) for every harness module whose sources hold an annotated file; run before the harnesses exist, it says so (`eva_taint.pending`), and the `seed` target's run sets it. `ledger.py ingest-eva` files each check's status under the function's `l6_no_leak` unit, never its `rte` unit: Unknown or Invalid blocks the unit and `ingest-wp` does not credit it until a later Eva run of that module leaves the check Valid. E-ACSL does not execute `\tainted` (it ignores the assertion), so Phase 1 checks nothing here.

---

## Known Limits

- **Pipeline integration:** `security_props.py run` is a `/framac-slice` step. The generated Makefile runs it as the `security-props` target, which `seed` depends on, and `benchmark.py` and `benchmark_seeded.py` run it as the `security_props` stage before the ledger seed.
- **L3 over-approximation:** a call to a libc memory writer counts as a pointer write even when its destination is local.
- **L5 on string literals:** `no_crlf_string` on a literal argument does not prove (checked again after S8), even with Alt-Ergo, Z3 and CVC5 at 10 s. A caller passing literals only is decided from the model instead; one that passes a sink both literals and other text keeps a goal its literal calls cannot discharge, and a pointer into a literal (`"abc" + 1`) counts as other text.
- **Forwarding sinks (L5):** see Layer 5. A wrapper declared without the function that transmits is still checked at its callers, before a callee completes the buffer; a wrapper with one undeclared backend keeps that placement and a warning.
- **Sinks called through a pointer (L6):** `L6_no_leak_<secret>` still uses `\called_arg` at every call. At a pointer call of a sink the target defines, its instance is `!(pointer == &sink)` and stays unproven. Only Layer 5 has the `\precond` form.
- **Instances MetAcsl decides statically:** MetAcsl drops an instance it simplifies to true (a literal or another global separated from the secret), leaving no goal. `ledger.py ingest-wp` credits such a unit when the WP run loaded every property it names and ended `all_proven`.
- **Wipes under the Typed model:** a `memset` of an `unsigned char` array does not prove; a loop with invariants does. `explicit_bzero` and `memset_s` prove for a `char` array only; an `unsigned char` or `uint8_t` array through them needs `Typed+cast`.
- **Returned secrets:** a secret of kind `return` gives a warning and no property; `REPORT.md` lists it under "Threat-model items without a property". Declare where the caller keeps the returned value instead (a global, a field, or a `local` of the caller).
- **Taint checks (`--eva-taint`):** off by default until a full pipeline run on a real target has used them. WP cannot prove `\tainted`, so `run_wp_function.py` leaves the `eva_taint` assertions out (`-wp-prop=-eva_taint`) when a source holds one; that filter also drops the kernel's Exit- and Termination-conditions from the run. A check sits only in the property's calling instances: a parameter secret handed to a callee that leaks it is not followed into the callee. A sink without a `length` is checked on its first byte (`strlen` in an annotation breaks E-ACSL builds). Eva's taint is a may-analysis: an Unknown check is a possible flow to review, not a confirmed leak.
