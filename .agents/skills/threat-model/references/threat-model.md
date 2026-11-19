# Source-Backed Threat Model

Build `ThreatModel.md` from `Context.md` and the registered inventory. Cite exact paths and symbols for material claims, label inference, and record unknown deployment facts.

## Contents

- [Method](#method)
- [`ThreatModel.md` contract](#threatmodelmd-contract)
- [Section rules](#section-rules)
- [Machine-readable block](#machine-readable-block)
- [Updating an existing model](#updating-an-existing-model)
- [Exit gate](#exit-gate)

## Method

Use the four threat-model questions:

1. What is being built?
2. What can go wrong?
3. What controls address it?
4. Is the analysis adequate for the confirmed scope and available evidence?

Work in this order, because each step uses the one before:

1. **Components and boundaries.** Group the scope into components (from "Directory Roles" and the public headers) and name each trust boundary by what changes when data crosses it: who controls the data, which privileges apply, which process or machine holds it.
2. **Actors.** For each deployment shape of `Context.md`, state who can reach the target and what they must already have (nothing, a network path, a local account, a valid credential, the ability to link against the library).
3. **API classification.** Class every exported function. This is the step that decides what the verification treats as attacker-reachable, so no function may be left out.
4. **Typed tables.** Turn the inventory rows into the entry-point, protection-mechanism, secret, gate, sink and state tables.
5. **Data flows.** Connect entry points and readers to the sinks and the state they can reach, and name the checks on each path.
6. **What can go wrong.** For each boundary crossing and each asset, state the threats, the control the source shows, and which property would rule the threat out.
7. **Adequacy.** Answer the four questions and list what the model does not cover.

## `ThreatModel.md` contract

Preserve these sections, in this order:

```markdown
# Threat Model — REVIEW_ID

## System And Deployment Context

## Components And Trust Boundaries

| Component | Paths | Role |
| --- | --- | --- |

| Boundary | What Changes On Crossing | Crossed By | Expected Control | Source Reference |
| --- | --- | --- | --- | --- |

## Assets And Security Properties

| Asset | Where Held | Required Security Property | Consequence Of Failure |
| --- | --- | --- | --- |

## Threat Actors And Starting Positions

| Actor | Starting Access | Prerequisite | Relevant Goal |
| --- | --- | --- | --- |

## API Classification

| Function | Declared In | Class | Reason | Source Reference |
| --- | --- | --- | --- | --- |

## Entry Points And Readers

| ID | Function | Role | Attacker-Controlled Parameters | Channel | Check In Front | Attacker Prerequisite | Source Reference |
| --- | --- | --- | --- | --- | --- | --- | --- |

## Protection Mechanisms

| Mechanism | Function | What It Protects | Source Reference |
| --- | --- | --- | --- |

## Secrets

| ID | Secret | Kind | Held Or Released In | Size | Wiped By | Source Reference |
| --- | --- | --- | --- | --- | --- | --- |

## Authorization Gates

| ID | Gate Function | State It Sets | Success Value | Protects | Source Reference |
| --- | --- | --- | --- | --- | --- |

## Output Sinks

| ID | Function | Kind | Data, Length And Format Parameters | Transmits Or Forwards To | Source Reference |
| --- | --- | --- | --- | --- | --- |

## State, Invariants And Call Order

| ID | State | Allowed Writers | Allowed Readers | Condition That Always Holds | Required Call Order | Source Reference |
| --- | --- | --- | --- | --- | --- | --- |

## Data Flows

| Flow | From | Through | To | Checks On The Path | Source Reference |
| --- | --- | --- | --- | --- | --- |

## What Can Go Wrong

| ID | Threat | Where | Control Observed | Property That Rules It Out | Carried By |
| --- | --- | --- | --- | --- | --- |

## Feature And Configuration Assumptions

## Unknowns And Evidence Limits

## Coverage Priorities

## Adequacy Check

- **What is being built:** ...
- **What can go wrong:** ...
- **What is being done about it:** ...
- **Is the analysis adequate:** ...

## Frama-C Threat Model Block

<one fenced `json framac-threat-model` block, or "Not applicable: no C code in scope.">
```

Do not weaken or delete a section because information is unavailable. State the unknown and how it affects coverage or confidence.

## Section rules

### Looked and found none

A table with no row holds one sentence instead: `None: <what was checked, and why nothing qualifies>`, for example `None: the library writes only into buffers its caller owns; no file, socket or log call exists in the scope (inventory pass 3, sink probes without a hit).` An empty table without that sentence is a hard error: nobody can tell "looked, none" from "not looked".

### API classification

List every function a public header declares or the build exports, plus `main`. Take the list from three sources and reconcile them: the public headers and export lists (version scripts, `.def` files, visibility attributes), what the documentation, the tests, the examples and the shipped fuzz targets call, and the inventory's entry-point rows. A function that only one source knows is resolved before the phase closes: either it joins the table or the row says why it is not part of the interface.

Each function gets exactly one class, and the class counts must add up to the number of listed functions; write the counts under the table.

| Class | Meaning | Evidence it needs |
| --- | --- | --- |
| `entry` | External code calls it with data an attacker may control. | The parameters that carry the data. |
| `reader` | It returns or fills outside data for its caller. | The buffer it fills, or the value it returns. |
| `trusted-only` | Exported, but only trusted code calls it. | Positive evidence: an internal header, documentation of an internal API, a naming rule the project documents, or callers confined to the target. A name that looks internal is not evidence. |
| `no-attacker-data` | External code calls it, and none of its parameters can carry attacker data (a constructor without arguments, a getter of a constant). | Why no parameter qualifies. |
| `unreachable-in-configuration` | The assumed build configuration does not compile or export it. | The option that removes it. |

The default is `entry`. A function leaves that class only with the evidence its new class needs: an exported function nobody could classify stays `entry` and gets a row in "Unknowns And Evidence Limits".

Export-only helpers deserve care: a library that exports functions only for its own inline wrappers or macros makes each of them look like an attacker-reachable entry point. Class them `trusted-only` when the header shows that the wrapper is the documented interface, and cite it.

### Entry points and readers

One row per `entry` and `reader` function of the classification, plus the readers the target does not define (a callback type the embedder implements, a platform receive function).

- **Channel:** how the data arrives: API call, socket, file, standard input, environment, command line, callback.
- **Check in front:** the validation or authorization that runs before the function, or `none`.
- **Attacker prerequisite:** one of `none`, `network path`, `local account`, `valid credential`, `physical access`, `control of the embedding application`. Use `none` only with positive evidence that the data is reachable without anything else; otherwise state what is needed, or `[UNKNOWN]`.

### Protection mechanisms

List the controls before the threats that rely on them: validators, bounds and length checks used across the code, wipe helpers, lock and unlock pairs, privilege drops, constant-time comparisons. The gate, state and "What Can Go Wrong" rows refer to these by name.

### Secrets, gates, sinks and state

- **Secrets:** only values the code holds in memory. A secret returned to the caller has no place the target can wipe: record where the caller is told to release it.
- **Gates:** a gate needs the functions it protects. A check that guards nothing privileged is a protection mechanism, not a gate.
- **Sinks:** one row for the function that finally transmits, and one for each wrapper that forwards to it. "Transmits Or Forwards To" says which is which. When a later function completes the buffer a wrapper forwards (a header or length filled in just before sending), say so: the data is complete only at the transmitting function.
- **State:** fill only the columns the source supports. "Allowed writers" is the set of functions (or the file) that the design lets write the state; "Condition that always holds" is a relation over globals that every function preserves (`count <= capacity`, `state` is one of its enumerators); "Required call order" is a condition that must hold when a function is called (initialized before use, a lock held).

### Data flows

One row per path from an entry point or reader to a sink, a secret or a state row. "Through" names the functions on the path that parse, copy or transform the data, each with its source reference. A sink or state row that no flow reaches is either unreachable from outside (say so) or a gap in the inventory (resolve it).

"Checks on the path" names the validation or authorization steps between the two ends. A check that sits on every path to a function is worth a row of its own: when it decides who may proceed it is an authorization gate, and when it establishes a condition the function relies on (initialized, locked, length validated) it is a required call order in the state table. A check that sits on some paths only is a threat row: say which path lacks it.

### What can go wrong

For each boundary crossing and each asset, ask what breaks its confidentiality, integrity, availability, or authorization, and write one row per distinct threat. This is not a list of findings: a row states what must not happen and what the design does about it, whether or not the code gets it right.

"Carried by" says who will check the property, in one of these forms:

- `default checks`: memory safety, arithmetic and termination, which the verification checks on every function without any block item;
- the block item that carries it (`secrets: session_key`, `auth_gates: en_check_token`, `output_sinks: en_log`, `assets: session_table`, `invariants: count_bound`, `call_rules: en_send`);
- `not checked by the verification`, with the reason: no block item can express it (a state row the `assets`, `invariants` or `call_rules` lists cannot state: name the row, `ST-NNN`), or it is outside what the verification looks at (timing side channels, cryptographic strength, protocol logic, races between threads, resource exhaustion other than non-termination, behaviour of the embedding application).

Only a block item, or the default checks, counts as carried. The rows marked `not checked by the verification` are the residual risk of the model. Repeat them under "Unknowns And Evidence Limits".

### Unknowns and evidence limits

Give each unknown a type, what it affects, and how to settle it:

- **Deployment:** a fact only the user knows (who links the library, which privileges it runs with).
- **Indirect reach:** function-pointer tables, run-time callbacks, macro-generated functions and dynamically loaded symbols whose targets or callers the source does not fix.
- **Configuration:** code that exists only under an option the review did not assume.
- **Unclassified interface:** an exported function left as `entry` for lack of evidence.
- **Not checked by the verification:** the residual threats.
- **Review gap:** deferred files, a review that was not independent, a block that was not machine-validated.

### Coverage priorities

Rank the components and functions the verification should reach first: the parsers of attacker data, the functions between an entry point and a secret or a gate, and the code a build option adds. Each priority cites the rows that justify it.

## Machine-readable block

The last section holds the structured block that the Frama-C verification pipeline reads through `--threat-model PATH`. Build it from the tables once they are final, following [Frama-C threat-model block](framac-threat-model.md), and validate it there.

The block restates the model; it never extends it.

- Every `input_sources` item matches a row of "Entry Points And Readers".
- Every `trusted_callers` item matches the `trusted-only` rows of "API Classification".
- Every `secrets` item matches a row of "Secrets".
- Every `auth_gates` item matches a row of "Authorization Gates".
- Every `output_sinks` item matches a row of "Output Sinks".
- Every `assets` item matches the "Allowed Writers" or "Allowed Readers" of a row of "State, Invariants And Call Order".
- Every `invariants` item matches the "Condition That Always Holds" of a row of that table.
- Every `call_rules` item matches the "Required Call Order" of a row of that table.
- Every empty list is backed by the `None:` sentence of its table. `assets`, `invariants` and `call_rules` are optional: leave one out when its column is empty.

Count them: the ledger's "Inventory Counts" must show, per kind, the rows found, the rows in the model, the items in the block and the rows dropped with their reason. A row that the block's schema cannot express (a returned secret, a state row the `assets`, `invariants` or `call_rules` lists cannot state) stays in the prose and is counted as dropped with that reason.

## Updating an existing model

When the user supplies an earlier `ThreatModel.md` of the same target as a baseline, record its path and sha256 in the ledger and build the new model from the source as usual. Do not copy rows from the baseline. When the new model is final, compare the two:

- keep the baseline's row IDs for rows that describe the same function and role, so that results tied to them stay valid;
- mark each row `unchanged`, `changed`, `new` or `removed`, and for a row the baseline lacked although the code was already there, `missed-in-baseline`;
- list the comparison under "Unknowns And Evidence Limits".

The pipeline records the sha256 of the file it used. A new model means re-running the pipeline's model, trust, call-graph and property steps.

## Exit gate

Close the phase only when:

- all four adequacy questions have source-backed answers;
- every exported function has one class, and the class counts add up;
- every table has rows or its `None:` sentence;
- every row cites its source, and every `inferred` claim says why;
- every sink and state row is reached by a flow or explained;
- every "What Can Go Wrong" row names who carries its property;
- coverage priorities are actionable;
- every placeholder is replaced.

Otherwise mark the phase partial or blocked with the missing evidence.
