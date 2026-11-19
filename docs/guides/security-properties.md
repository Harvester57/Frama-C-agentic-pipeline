# Proving Security Properties Beyond Memory Safety (Layers 1 to 6)

While the `-rte` plugin automatically generates proof obligations for **Layer 1 (Absence of Run-Time Errors / Memory Safety)**, many critical security vulnerabilities in C—such as SNMPv3 authentication bypasses, infinite-loop Denial-of-Service, Syslog CRLF log injection, and cryptographic key leaks—are 100% memory-safe and trigger zero RTE alarms.

This pipeline extends Frama-C verification across **six distinct security layers**. Layers 1 and 2 are checked statically (`Eva`, `WP`) and dynamically (`E-ACSL + LibFuzzer`); Layers 3 to 6 are proved by `WP`, and, when `meta_engines` asks for it, also checked by Eva on each module and compiled into the fuzz build (see "MetAcsl under Eva" and "MetAcsl in the fuzz build" below).

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
2. Each property is rendered from [`templates/metacsl/`](../../templates/metacsl/) as a MetAcsl meta-property, and lists its `instances`: the functions where its generated annotations land. Those are the ledger units (`l3_frame`, `l4_auth_state`, `l4_auth_required`, `l5_sanitized`, `l6_wiped`, `l6_no_leak`), seeded by `ledger.py seed`. The asset, invariant and call-rule properties add the classes `l3_isolation`, `l4_invariant` and `l4_call_rule`.
3. `run_wp_function.py` loads the properties of the function under proof (`--security-props`, default the run's file; `none` turns it off) and runs `-meta -then-last -wp`. A prover discharges the generated `assert`, `requires` and `ensures` named `<property>: meta:` like any other goal, and the prover brief lists what to discharge.

Without a threat model only Layer 3 is generated.

### Other engines: `meta_engines` and the module meta file

WP always checks the properties. Eva and E-ACSL check them on a whole module when the run asks for it ([`../plans/metacsl-exploitation-plan.md`](../plans/metacsl-exploitation-plan.md), packages B and C; see "MetAcsl under Eva" and "MetAcsl in the fuzz build" below):

- **The switch.** `security_props.json` has `meta_engines`, a list within `eva` and `eacsl`. `security_props.py run --meta-engines eva,eacsl` sets it, `--meta-engines none` clears it, and a plain run keeps the previous choice, so the Makefile's `security-props` target does not undo it. `security_props.meta_engines(props)` reads it. Absent or empty means WP only, which is the default.
- **The module meta file.** `security_props.module_meta_file_text(props, functions=None)` returns `(text, names, sources)`, or `None` when there is nothing to load: the meta file of a whole-module run, where MetAcsl instantiates each property in every function of the parse. `functions` is a list of `file#name` ids and selects the properties with an instance among them; `None` selects every property with an instance. A property without instances (decided from the model, or a forwarding sink) and a property written into the work tree (`code`) are left out. The layout is the one of a function's meta file (`meta_file_text`), so `security_props.meta_line_names(text)` maps the line of a report row back to its property.

A threat model block looks like this (fields per kind: `input_sources` `function`, `role`, `params`; `trusted_callers` `unit`, `except`, `functions`, `reason`; `secrets` `name`, `kind` (`global`, `parameter`, `field`, `local`, `return`), `function`, `size`, `object`; `auth_gates` `function`, `state`, `protects`, `success`; `output_sinks` `function`, `kind`, `params`, `length`, `format`; the optional `assets`, `invariants` and `call_rules` are described under "Assets, Invariants and Call Rules" below):

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

The properties name the canonical vocabulary of `templates/acsl/acsl_vocabulary.h` (plan step S8) and define no predicate of their own: `no_crlf_string(s)` (a NUL-terminated string, bounded by `strlen`) and, for a length-bounded buffer, `no_crlf_or_nul(buf, len)`. The meta file does not include the vocabulary header, so its preamble takes `strlen` from `__fc_string_axiomatic.h` and repeats `no_crlf_string` with the vocabulary's exact text (Frama-C merges identical definitions; `test_preamble_repeats_the_vocabulary_text` keeps the two equal). E-ACSL executes `no_crlf_string` through `strlen` where a contract names it, and a `\calling` text-sink property compiled into the fuzz build stops the binary on a violation (`L5_sanitized_logmsg` in `test_in_the_image_each_planted_violation_is_reported_under_its_property`). The in-code checks at initializer calls are not written for text sinks (see "Calls placed in initializers").

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

## Assets, Invariants and Call Rules

Three optional lists of the threat model state properties that are not tied to a gate, a sink or a secret (package D1 of [`../plans/metacsl-exploitation-plan.md`](../plans/metacsl-exploitation-plan.md)). A threat model without them generates what it did before.

```json
"assets": [
  {"name": "config", "lvalue": "config", "writers": ["set_config"], "readers": ["get_config"], "description": "..."},
  {"name": "mode", "lvalue": "c->mode", "params": ["conf"], "writers": ["conf_set_mode"], "description": "..."}
],
"invariants": [
  {"name": "count_bound", "variant": "weak", "predicate": "count <= limit", "scope": ["add", "remove"], "description": "..."},
  {"name": "phase_up", "variant": "monotonic", "lvalue": "phase", "direction": "up", "description": "..."}
],
"call_rules": [
  {"function": "write_reg", "predicate": "idx < 8 && ready != 0", "description": "..."}
]
```

| List | Property | Class | MetAcsl context | Template |
| :--- | :--- | :--- | :--- | :--- |
| `assets` | `L3_writers_<name>`: only the `writers` write `lvalue` | `l3_isolation` | `\writing` over every other function | [`l3_asset.acsl`](../../templates/metacsl/l3_asset.acsl) |
| `assets` with `readers` | `L3_readers_<name>`: only the `readers` read it | `l3_isolation` | `\reading` over every other function | same |
| `invariants` | `L4_invariant_<name>` | `l4_invariant` | `\weak_invariant`, `\strong_invariant`, `\conditional_invariant`, or `\writing` (monotonic) | [`l4_invariant.acsl`](../../templates/metacsl/l4_invariant.acsl) |
| `call_rules` | `L4_call_<callee>`: `predicate` holds at every call of the callee | `l4_call_rule` | `\calling`, or `\precond` on a callee called through a pointer | [`l4_call_rule.acsl`](../../templates/metacsl/l4_call_rule.acsl) |

Each property has a `variant` in `security_props.json`:

- **Assets: `global` or `formal`.** An `lvalue` that starts at a global (`config`, `session.mode`) is named as it is. One that starts at a parameter (`c->mode`) is checked in the functions that have a parameter of that name, through `\tguard(... \formal(c)->mode ...)`; `params` lists the other names the object is passed under, one clause each. A function that takes the object under a name the threat model does not list is not checked, and a name no function has is left out with a warning (its clause would be true everywhere).
- **Invariants.** `weak`: the predicate holds at the entry and exit of each function in `scope` (a `requires` and an `ensures`; the `requires` is proved in the callers, which are instances too). `strong`: it also holds after every statement. `conditional`: a function that is entered with it keeps it (a behavior named after the property; nothing is asked of the callers). A conditional invariant needs a `scope`. `monotonic` takes an `lvalue` and a `direction` (`up` by default) instead of a predicate: at every write, either the write is separated from the lvalue or `\at(x, Before) <= \at(x, After)`; `monotonic_formal` is the same for an lvalue reached from a parameter.
- **Call rules: `global`, `formal` or `entry`.** A name in the predicate that is a parameter of the callee stands for the argument of the call (`\called_arg`, variant `formal`); any other name is a global (`global`). A callee the target defines and calls through a function pointer gets the rule as its precondition (`entry`), like a Layer 5 sink: a pointer call then needs `/*@ calls callee; */`.

**The instance count is bounded by `scope`.** Without a `scope` an invariant targets every function of the build, and each is a ledger unit to prove. Above 50 instances the generator warns and names the count. An `L3_readers_*` property has every function but the readers as instances (any function may read the asset through a pointer) and warns the same way.

**What goes into an annotation is validated.** `lvalue` is a name followed by `.field` or `->field` steps. A `predicate` is at most 400 characters of ACSL expression text: no `;`, no comment markers, no `\result`, no `\flags`, `proof:`, `\tguard`, `\inter` or `\in_file` ([`../../schemas/threat_model.schema.json`](../../schemas/threat_model.schema.json), and `security_props.predicate_problem` for a block that did not go through the schema). `trust.py check-threat-model` also says which fields go with which invariant variant, and checks the new names against the model: writers, readers and scope functions the build does not define, an lvalue that starts at neither a global nor a parameter, and predicate names that are neither globals nor parameters of the callee. A parameter name that is misspelt in a call rule would otherwise be read as a global that does not exist, and the `\fguard` would turn the property into `\false`.

**Generated text is guarded.** `security_props.meta_text_problems` refuses a property whose text holds `\inter` or `\in_file` in `\targets` (the scope is computed in Python and listed by name), a `proof:deduce` or `proof:axiom` flag, or `\result` under `\tguard` (it would be silently true). Such a property is not generated and the warning names it. The findings behind these rules are in package R of the plan.

**Engines.** A monotonic invariant has `engines: ["eacsl"]`: Eva does not evaluate `\at(x, Before)`. `security_props.for_engine(props, "eva")` returns the document without the properties an engine may not load. `run_eva_slice.py` (engine `eva`) and `fuzz_build.py` (engine `eacsl`) apply it before they write the module meta file, and list the names they left out under `not_for_engine` in their report's `security_props`; with no such property the commands, the meta file and the reports are the ones they were. A property without `engines` is for every engine. WP always loads them all.

### Declared callees and `\writing` properties

At a call, MetAcsl's `\writing` context takes what is written from the callee's `assigns`. For a function the target only declares, that has three consequences, which the generator handles for every `\writing` property (`L4_auth_state_*`, `L3_writers_*`, monotonic invariants). It reads the `assigns` of each declared callee textually at its first declaration (`external_decls` of the model, resolved under the work tree, the model's tree, or Frama-C's share directory), because the Phase 0 parse runs with `-no-annot` and the model holds no contract.

- **An `assigns` that holds a set** (`\union(*a, *b)` or `{*a, *b}`) stops MetAcsl 0.12 (`meta_annotate.ml`, line 675). The callers of such a callee are left out of the property's `\targets` and listed under the property's `unchecked`, each with an obligation entry that carries `unchecked`, and a warning names the callees. Nothing checks those callers until the contract is rewritten with one term per location. A WP run that still meets such a contract (one written after the generator ran, or in a header the generator did not read) ends `analysis_error` with reason `metacsl_set_assigns`: `run_wp_function.py` recognises `Unexpected error (File "meta_annotate.ml", line 675, ...)`, whose log names no callee, and its `metacsl_failure` and hint name the functions declared in the sources and their quoted includes whose `assigns` holds `\union`, `\inter` or `{`. Re-running does not help; rewrite the contract.
- **No `assigns` at all:** MetAcsl generates nothing for what the callee writes and prints no warning. The property lists the callee and its callers under `declared_callees.no_assigns`, with a warning.
- **A declaration that cannot be read** (no `external_decls` entry, a file outside the roots): `declared_callees.unknown`.

A caller of a declared callee that assigns something is an instance of the property. A contract written later (by a Phase 3 prover, or on a second declaration) is not seen by the generator: re-run `security_props.py run` after such a change.

### Calls placed in initializers

MetAcsl 0.12 generates no `\calling` instance, no `\writing` instance from the callee's `assigns` and (with its default simplification) no `\strong_invariant` assertion at a call placed in an initializer (`int n = net_send(fd, buf, 16);`). The Phase 0 dump (`phase0_dump.ml`, dump schema 5) marks each direct call site with `initializer`, and for every property whose context is skipped there the generator lists the site under `init_checks`. `security_props.py run` writes an ordinary `check`, named after the property, on the line of the declaration (before it, or after it for a strong invariant), with the argument texts in place of the parameters:

```c
/*@ check L5_sanitized_net_send: \initialized(((char const *)(buf)) + (0 .. (16) - 1)); */ /*@ check L6_no_leak_key: \separated(((char const *)(buf)), &key); */ int n = net_send(fd, buf, 16);
```

A pointer argument is cast to its parameter's type (`((char const *)(buf))`), because ACSL does not convert an array to a pointer and an annotation that does not type stops the function's whole WP run. The placed checks are in `code_checks`, each with the line it is written on and its `index` among the generated checks of that line; WP proves them with the function. That E-ACSL executes them was not tried.

Frama-C's CSV gives a `check` its file and line only. `run_wp_function.py` names the check rows of a line from `code_checks` (the function's entries, by file, line and `index`): the rows of one line come in index order (checked in the image on the initializer fixture), so a row reads `L5_sanitized_net_send: \initialized(...)` and is credited to the property's class. A line whose check rows do not match its checks in number, or whose indexes repeat, stays unnamed and is listed under `security_props.code_checks_unnamed`. `ledger.py` keys `code_checks` by (file, line, index) and files an Eva row of a line under every check of that line.

The ledger never credits a unit whose property `security_props.json` says is not checked in the function: a site under the property's `unchecked`, an obligation entry with `unchecked`, or an `init_checks` site with no placed check. `ingest-wp` gives such a unit the evidence `wp_meta_unchecked` and blocks it, whatever the run proved, with the reasons under `unresolved`; `ingest-eva` does not cover it. A function with placed checks whose run reports none of them gets `wp_meta_check_not_reported` instead of the no-goal credit (see Known Limits). Under Eva, an open in-code check of the unit's property keeps the unit from an Eva cover. The property keeps its MetAcsl text for the statement calls. A site whose check cannot be written (the call is not the whole initializer of a one-declarator declaration, an argument holds a call or an assignment, a macro hides the call, the parameters, their types or the callee's `assigns` are unknown, the check would name a global the function's file does not define, the sink is a text sink, or the property is a transition) moves to the property's `unchecked`, with the reason. `\precond`, `\postcond`, `\reading`, weak and conditional invariants need no such check: MetAcsl handles them at initializers.

A model that does not flag every call site gives no `init_checks` for the unflagged sites and, when it records call sites, a warning (`call sites do not say which calls are initializers`) that `REPORT.md` repeats at the top. `security_props.json` records the answer in `initializer_flags`: `{"known": true}`, or `{"known": false, "properties": [...]}` with the properties whose context MetAcsl skips at such a call (`\calling`, `\writing`, `\strong_invariant`). A model that records no call sites at all is unknown too. `ledger.py ingest-wp` refuses the units of those properties the no-goal credit (`wp_meta_initializers_unknown`), because "MetAcsl left no goal" says nothing about a call it never looked at. A property of `\reading`, `\precond`, `\postcond` or a weak or conditional invariant is not listed, and a goal WP proves still credits its unit. A `security_props.json` older than the field cannot say which model it came from: every MetAcsl unit is refused that credit until `security_props.py run` rewrites the file.

---

## MetAcsl under Eva

With `eva` in `meta_engines` (`security_props.py run --meta-engines eva`), every Eva run of a module checks the module's properties too: the plain run, the base run, each tuning rung, each shard and the loop trials. Without it the command and the report are the ones of a run without the option.

- **Options.** `gen` writes `EVA_SECURITY_PROPS_<mod>` into `modules.mk` and the recipes pass `--security-props=<file>`. By hand, `run_eva_slice.py` takes `--security-props PATH`, else `$FRAMAC_SECURITY_PROPS`, else `workspace/reports/security_props.json` when it exists; `--security-props none` turns it off.
- **What is loaded.** `security_props.for_engine(props, "eva")`, then one meta file with every property that has an instance in a function of the module's sources (the files they `#include` count), written to `workspace/reports/security_meta/<digest>/security_meta_<mod>.c`. MetAcsl runs before `-rte` with `-meta -meta-checks`, so a violated instance is a `check` and does not stop the analysis behind it.
- **The report's `security_props`.** `properties` loaded; `instances` (property, class, instance, `file#function`, with the generated checks counted per status: all zeros means MetAcsl generated nothing there); `open_rows` (the Invalid, unclassified and Unknown rows, named `<property>: meta: <predicate>`); `outside_instances` (checks in harness code, listed and never filed); `unplanned_instances` (target functions the model does not list as instances: the model and MetAcsl disagree); `error`, with `error_summary` and `failed_log` (`eva.meta_failed.log`), when the file could not be read or Frama-C failed with the properties, and the report is the run without them; `skipped` (a property naming a global whose file is not in the work tree); `not_for_engine` (properties left out for Eva). These rows are in none of the RTE status buckets.
- **The ledger.** `ingest-eva` gives each `l3_isolation`, `l4_*`, `l5_*` and `l6_*` unit with a planned instance in the report a verdict from its properties' checks: all Valid covers the unit (`eva_meta_valid`, with the harness-context assumption); an Invalid check makes it a candidate (`eva_meta_invalid`, one candidate per Invalid row); Unknown, Dead, unclassified or no check (`eva_meta_unknown`, `eva_meta_dead`, `eva_meta_unclassified`, `eva_meta_no_instance`) leave it for WP. A unit the model decided violated, whose taint check is open, whose property is not checked in the function (`unchecked`), or whose in-code check is open is not covered this way. A unit whose property Eva left open in a module also loses the WP no-goal credit (`wp_meta_simplified_eva_open`). When WP gave that credit first, `ingest-eva` withdraws it (`eva_no_goal_credit_withdrawn`): the credit's evidence stops discharging and a covered unit goes back to `planned`. A cover behind a goal WP proved stays.
- **The cache.** An Eva result with properties is cached under a key that adds the meta file's text and a digest of what decides how the rows are filed (`run_eva_slice.META_STATIC_KEYS`: the properties, their classes, planned instances and decided functions, the module's functions and roots). The key of a run without properties is what it always was.

## MetAcsl in the fuzz build

With `eacsl` in `meta_engines`, the E-ACSL build of a module compiles the module's properties into run-time checks: an input that violates one stops the binary like any other failed check. Without it the Make output, the commands and the reports are the ones of a build without the option.

- **Options.** `gen` writes `FUZZ_SECURITY_PROPS_<mod>` into `modules.mk`; the `build-<mod>` and `fuzz-<mod>` recipes pass `--security-props=<file>` and `build-<mod>` depends on it. By hand, `run_eacsl_fuzz.py`'s `build`, `campaign`, `replay`, `minimize`, `replay-candidates` and `minimize-candidates` take `--security-props PATH`, else `$FRAMAC_SECURITY_PROPS`, else the run's file; `none` turns it off.
- **What is loaded.** `security_props.for_engine(props, "eacsl")`, restricted to the properties with an instance in the module's sources, written to `<out-bin>.security_meta.c` with a sidecar `<out-bin>.security_meta.json` (property to class and instances, function to file, the harness's functions). MetAcsl runs in a Frama-C stage of its own before RTE and E-ACSL. The sanitizer build, the guardrail, the selftest canary and the loop-seed check never load them.
- **The report's `security_props`** (build, campaign and replay reports, with `security_props_warnings`, each also printed as `security props [<mod>]: ...`): `status` `loaded`, `dropped` (the build failed with the properties and was redone without them; `log` names `<out-bin>.security_meta.log`; not cached), `error` (the file could not be read) or `skipped`; per property `rejected` (MetAcsl could not type it in this module), `left_out` (a `\precond` property whose protected function the harness names), `not_translated` (no run-time check exists); `unplanned_instances`; `not_for_engine`.
- **A violation.** Its failure carries `meta_property`, `obligation_class`, `line: 0` and `meta_location`; its fingerprint is `<file>#<function>::meta_<property>::<hash>` and does not depend on where the meta file was written. A failed `\precond` is reported in the protected function with its `caller`; with `harness_induced: true` the caller is harness code, the campaign report lists it under `security_props_harness_induced`, and it is not a finding against the target. A failed guard (`meta_guard`) is an ordinary alarm (class `rte`), not a violation of the property.
- **The ledger.** A campaign whose build lost the properties (`dropped`, `error`, a toolchain `skipped`) gives the module's units of the MetAcsl classes `fuzz_meta_not_checked`, and the command's output repeats the report's warnings. `ingest-fuzz` (`_fuzz_meta_route`) makes a violation a candidate on the unit of the property's class in the failing function; a failed precondition links its `caller`'s unit; a harness-induced one makes no candidate (`meta_harness_induced` in the output); an unplanned instance links no unit; a failed guard is class `rte`.
- **The cache.** A build with properties is cached under its own key: the meta file's text, the MetAcsl stage flags and what the sidecar is written from (not the path of `security_props.json`). A hit restores the meta file and the sidecar with the binary. The key of a build without properties is what it always was.

---

## Known Limits

- **Initializer flags come from the dump.** `phase0_model.py` copies the dump's `initializer` into each call site. A model built from an older dump (schema below 5) has none: the generator writes no in-code check and records `initializer_flags`, and the ledger refuses the no-goal credit (`wp_meta_initializers_unknown`). That refusal is all it does: a function with a proven goal of the class, or an Eva cover, is still credited although a call in one of its initializers may be unchecked (see [`../troubleshooting/security-properties.md`](../troubleshooting/security-properties.md)). Rebuild the model to close it.
- **In-code checks are named by position.** A check row is named only when its line has as many check rows as `code_checks` entries; otherwise it stays unnamed (`code_checks_unnamed`) and is credited to no property.
- **Parameter-held assets** are checked only under the listed parameter names.
- **Readers properties are broad:** every function but the readers carries a unit.

- **Pipeline integration:** `security_props.py run` is a `/framac-slice` step. The generated Makefile runs it as the `security-props` target, which `seed` depends on, and `benchmark.py` and `benchmark_seeded.py` run it as the `security_props` stage before the ledger seed.
- **L3 over-approximation:** a call to a libc memory writer counts as a pointer write even when its destination is local.
- **L5 on string literals:** `no_crlf_string` on a literal argument does not prove (checked again after S8), even with Alt-Ergo, Z3 and CVC5 at 10 s. A caller passing literals only is decided from the model instead; one that passes a sink both literals and other text keeps a goal its literal calls cannot discharge, and a pointer into a literal (`"abc" + 1`) counts as other text.
- **Forwarding sinks (L5):** see Layer 5. A wrapper declared without the function that transmits is still checked at its callers, before a callee completes the buffer; a wrapper with one undeclared backend keeps that placement and a warning.
- **Sinks called through a pointer (L6):** `L6_no_leak_<secret>` still uses `\called_arg` at every call. At a pointer call of a sink the target defines, its instance is `!(pointer == &sink)` and stays unproven. Only Layer 5 has the `\precond` form.
- **Instances MetAcsl decides statically:** MetAcsl drops an instance it simplifies to true (a literal or another global separated from the secret), leaving no goal. `ledger.py ingest-wp` credits such a unit (`wp_meta_simplified`) when the WP run loaded every property it names and ended `all_proven`, unless Eva left a check of the unit's properties open in a module (`wp_meta_simplified_eva_open`), the property is not checked in the function (`wp_meta_unchecked`), in-code checks were written into it that the run did not report (`wp_meta_check_not_reported`), or the model does not say which calls are initializers (`wp_meta_initializers_unknown`). An Eva report that leaves such a check open after the credit was given withdraws it (`eva_no_goal_credit_withdrawn`).
- **Wipes under the Typed model:** a `memset` of an `unsigned char` array does not prove; a loop with invariants does. `explicit_bzero` and `memset_s` prove for a `char` array only; an `unsigned char` or `uint8_t` array through them needs `Typed+cast`.
- **Returned secrets:** a secret of kind `return` gives a warning and no property; `REPORT.md` lists it under "Threat-model items without a property". Declare where the caller keeps the returned value instead (a global, a field, or a `local` of the caller).
- **Taint checks (`--eva-taint`):** off by default until a full pipeline run on a real target has used them. WP cannot prove `\tainted`, so `run_wp_function.py` leaves the `eva_taint` assertions out (`-wp-prop=-eva_taint`) when a source holds one; that filter also drops the kernel's Exit- and Termination-conditions from the run. A check sits only in the property's calling instances: a parameter secret handed to a callee that leaks it is not followed into the callee. A sink without a `length` is checked on its first byte (`strlen` in an annotation breaks E-ACSL builds). Eva's taint is a may-analysis: an Unknown check is a possible flow to review, not a confirmed leak.
