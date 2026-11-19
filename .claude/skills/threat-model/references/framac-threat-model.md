# Frama-C Threat-Model Block

`ThreatModel.md` ends with one machine-readable block that the Frama-C verification pipeline reads.

- **How the pipeline finds it:** its trust boundary (`scripts/trust.py`) loads the file named by `--threat-model PATH`. The file name does not matter; the pipeline reads only the fenced block whose info string contains `framac-threat-model`.
- **What the block does:** it marks the untrusted entry points, the input readers, the trusted-only callers, and the secrets, authorization gates and output sinks that the pipeline turns into security properties.
- **Authority:** the pipeline's `schemas/threat_model.schema.json` defines the block. This page summarises it. Where they disagree, the schema wins; record the disagreement as a limitation.

## When to write it

- **C or C++ code in scope:** write the block. The pipeline analyses C, so name only C functions.
- **No C code in scope:** write the section with the sentence `Not applicable: no C code in scope.` and no block.

Every entry must restate a fact that the tables of `ThreatModel.md` already establish with a citation. The block adds no new claim. An empty list states that the target has none of that kind, so it needs the same evidence as a non-empty one: the `None:` sentence of the matching table.

The block carries only the kinds of fact its schema has a list for. A fact without a list (a returned secret, and any row of "State, Invariants And Call Order" while the schema has no list for it) stays in the prose and is counted as dropped, with that reason, in the ledger's inventory counts. Read the schema when it is available: a list it defines and this page does not describe is a disagreement to record, and the schema wins.

## Format

Put the block under a `## Frama-C Threat Model Block` section, after `## Adequacy Check`.

- Exactly one block per file.
- The fence starts at the left margin: not inside a list item or a quote.
- Open the fence with ```` ```json framac-threat-model ```` and close it with ```` ``` ````.
- The body is one plain JSON object: no comments and no trailing commas.
- Lines end with LF.

## Fields

The top-level keys are `schema_version`, `target`, `summary`, `input_sources`, `trusted_callers`, `secrets`, `auth_gates` and `output_sinks`.

- **Required keys:** `schema_version` (always `1`) and the four lists `input_sources`, `secrets`, `auth_gates` and `output_sinks`.
- **Recommended keys:** `target` (the project name), `summary` (one sentence) and `trusted_callers`.
- **Optional lists:** `assets`, `invariants` and `call_rules` (see below). Leave a list out when the model established nothing of that kind.
- **No other keys are allowed**, at the top level or inside an item.

### Naming rules

- **Functions:** write a function as `name`, or as `file#name` with `file` relative to the target root. Use `file#name` for a `static` function or for a name defined more than once.
- **`params`, `object` and `length`:** these are C identifiers. Copy them from the function's prototype.
- **`unit`:** a link unit of the build, such as `build/libfoo.a` or `libfoo.a`. Use it only when the build is known; otherwise list `functions`.
- **`description`:** every item needs a non-empty `description`. End it with the source reference, for example `(src/net.c:40-88)`, so each entry traces back to evidence.

### `input_sources`: where attacker-controlled data enters

Each item has `function`, `role` and `description`, plus optional `params`.

- **`entry`:**
  - The function's parameters carry attacker data, so it is an untrusted entry point.
  - List the attacker-carrying parameters in `params`. Leave `params` out only when every parameter carries attacker data.
  - Use it for every `entry` row of the "Entry Points And Readers" table. That includes public conversion helpers applied to values parsed from attacker input.
- **`reader`:**
  - The function returns or fills attacker data for its caller, like `read(2)`. Its callers and everything they reach are on the input path.
  - A reader may be external, for example an I/O callback type's implementation or a platform receive function.
  - The pipeline already treats `read`, `recv`, `recvfrom`, `fread`, `fgets`, `getline`, `getenv` and their close relatives as readers. List a reader only when the target's own or third-party functions play that role.

### `trusted_callers`: functions that only trusted code calls

Each item has `reason` and exactly one of `unit` or `functions`.

- **What it does:** it overrides every untrusted rule, so name only functions whose only callers are trusted.
- **Sources:** the `trusted-only` rows of the "API Classification" table, and nothing else.
- **Evidence:** the source must show the restriction, for example an internal header, a documented internal API, or a call graph confined to trusted code. Never infer it from a name.
- **`except`:** goes with `unit` and lists the functions of that unit that stay untrusted.
- **Default:** use `[]` unless the model established such a restriction.

### `secrets`: data that must not leak and must be wiped

Each item has `name`, `kind` and `description`.

- **`kind`** is one of:
  - `global`
  - `parameter`
  - `field`
  - `local`: an array local of `function`.
  - `return`
- **`function`:** where the secret is held, or released (for a `global`). Its wipe is checked when that function returns.
- **`size`:** the number of elements to wipe, as a C expression over constants and the function's parameters (`len`, `32`). It must not contain `/*`, `*/` or `//`.
- **`object`:** for a `field`, the parameter or global that holds the field.
- **Sources:** take these from the "Secrets" table, and only for values the code holds in memory. Use `[]` when the model shows that the target holds no secret.

### `auth_gates`: checks that must pass before privileged functions run

Each item has `function`, `protects` (at least one function) and `description`.

- **`state`:** optional; the variable or field that the gate sets, such as `ctx->authenticated`.
- **`success`:** optional; the value the gate returns when the check passed, such as `0`, `1` or `AUTH_OK`.
- **Sources:** take these from the "Authorization Gates" table. Use `[]` when the target has no access control.

### `output_sinks`: where the target's output leaves it

Each item has `function`, `kind` and `description`.

- **`kind`** is one of `network`, `file`, `log`, `terminal`, `ipc`, `buffer` or `other`.
- **`params`:** optional; the parameters that carry the output. The default is the pointer parameters.
- **`length`:** optional; the parameter that gives the number of elements `params` point to.
- **`format`:** optional; the parameter that holds a printf-style format. Every call must then pass a string literal there.
- **`checked_at`:** optional; for a wrapper sink only. A wrapper sink completes the buffer itself (a header length, a checksum) and then hands it to other sinks. List those sinks here; each must have its own item in `output_sinks`. The initialized-bytes property is then checked inside the wrapper, before each call that hands the buffer on, instead of at the wrapper's callers. Use it only for a sink the target defines, and not for `kind` `log`, `terminal` or `buffer`. The pipeline checks the claim against its model and keeps the property at the callers when the claim does not hold.
- **What counts:** output that leaves the target, such as writes to sockets, files, logs or the terminal, or callbacks that hand data out. A library that writes only into structures its caller owns has no output sink.
- **Sources:** take these from the "Output Sinks" table, one item per row. When a wrapper forwards its buffer to a function that transmits, list both, and say in each `description` which one forwards and which one transmits, and whether anything completes the buffer in between (a header or a length filled in just before sending). Never list the wrapper alone: the output is complete only at the transmitting function.

### `assets` (optional): state that only named functions may write or read

Each item has `name`, `lvalue`, `writers` and `description`.

- **`lvalue`:** a global (`config`, `session.mode`) or a field reached from a parameter (`c->mode`): a name followed by `.field` or `->field` steps, nothing else.
- **`writers`:** the functions allowed to write it. Every other function is checked.
- **`readers`:** optional; the functions allowed to read it. Leave it out when reads are not restricted: with it, every other function of the build is checked.
- **`params`:** optional; for an `lvalue` reached from a parameter, the other parameter names the same object is passed under.

### `invariants` (optional): predicates the code keeps

Each item has `name`, `variant` and `description`.

- **`variant`** is one of:
  - `weak`: the `predicate` holds when each function in `scope` is entered and when it returns.
  - `strong`: it also holds after every statement of those functions.
  - `conditional`: a function in `scope` that is entered with the `predicate` returns with it. It needs a `scope`.
  - `monotonic`: the `lvalue` only moves in one `direction` (`up`, the default, or `down`). It takes an `lvalue` and no `predicate`.
- **`predicate`:** an ACSL predicate over globals, such as `count <= limit`. At most 400 characters; no `;`, no comment markers, no `\result`.
- **`scope`:** the functions the invariant is stated on. Give one whenever the model allows: without it, every function of the build is checked.

### `call_rules` (optional): what must hold whenever a function is called

Each item has `function`, `predicate` and `description`.

- **`predicate`:** an ACSL predicate over the globals and the parameters of `function`; a parameter name stands for the argument of each call (`idx < 8 && ready != 0`). The same limits as an invariant's `predicate` apply.

## Example

This is an illustration for a small network library, not a template to copy:

```json
{
  "schema_version": 1,
  "target": "examplenet",
  "summary": "Packet parser and session layer; every received byte is attacker-controlled.",
  "input_sources": [
    {"function": "en_parse_packet", "role": "entry", "params": ["buf", "len"], "description": "Parses a received packet from the caller's buffer (src/packet.c:40-131)."},
    {"function": "en_transport_recv", "role": "reader", "description": "Transport callback that fills the receive buffer from the socket (src/io.c:12-30)."}
  ],
  "trusted_callers": [
    {"functions": ["src/session.c#en_session_reset"], "reason": "Called only from en_session_close after validation (src/session.c:210-232)."}
  ],
  "secrets": [
    {"name": "key", "kind": "field", "object": "sess", "function": "en_session_close", "size": "32", "description": "Session key held in struct en_session (include/en.h:44-52)."}
  ],
  "auth_gates": [
    {"function": "en_check_token", "state": "sess->authenticated", "protects": ["en_admin_command"], "success": "0", "description": "Token check that must pass before admin commands (src/auth.c:18-60)."}
  ],
  "output_sinks": [
    {"function": "en_log", "kind": "log", "format": "fmt", "description": "printf-style diagnostic log (src/log.c:8-25)."}
  ]
}
```

In `ThreatModel.md`, the same object goes in a fence whose info string is `json framac-threat-model`.

## Validate

The pipeline's validator only reads the file. It is not a command of the target repository.

1. **Run the validator if it is available.** It sits in the pipeline checkout, or at `/opt/framac-pipeline/scripts/trust.py` inside the pipeline's containers:

   ```text
   python scripts/trust.py check-threat-model <review-dir>/ThreatModel.md
   ```

   - **Exit 0:** valid.
   - **Exit 1:** no block was found.
   - **Exit 2:** the block is invalid. Fix the listed errors and run it again.
   - **Model check:** with `--model <run>/workspace/reports/phase0_model.json` from an existing pipeline run, it also warns about names that are not functions of the build. Resolve those warnings, or record why a name is external.

   Save the command and its output as `evidence/validation/check-threat-model.txt`, and run it again after every later change to the block.
2. **If the validator is not available,** check the block by hand against the rules above. Record that it was not machine-validated as a completeness gap of the block phase.

## Hand-off to the pipeline

- **Commands:** pass the file itself to the pipeline:
  - `phase0_model.py run --threat-model PATH`
  - `trust.py run --threat-model PATH`

  Use the path as the pipeline's container sees it. With the target mounted at `/target`, that is `/target/.security-reviews/<review-id>/ThreatModel.md`. A copy saved as `THREAT_MODEL.md` in the run's `workspace/` is also found without the flag.
- **Edits after a run:** the pipeline records the file's sha256 and refuses the file once it changes. After a pipeline run has used the file, any edit to `ThreatModel.md` means re-running the model, `trust.py run`, the call-graph DAG and the security properties. Say so in the hand-off.
