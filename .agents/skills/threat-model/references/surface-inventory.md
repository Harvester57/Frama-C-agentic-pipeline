# Surface Inventory

Read every eligible file and record what the threat model is built from: where data comes in, where it goes out, what must stay secret or intact, and what guards it. The inventory is the completeness evidence of the model: a function the inventory missed is a function the verification will treat as trusted, or never check.

This phase collects facts. It does not judge whether the code is correct, and it reports no vulnerability.

## Contents

- [Pass design](#pass-design)
- [Row kinds](#row-kinds)
- [Search probes](#search-probes)
- [Partition and dispatch](#partition-and-dispatch)
- [Complete assignment result](#complete-assignment-result)
- [Register receipts](#register-receipts)

## Pass design

Default to three passes. Each pass must account for every eligible file; sampling by risk is not full coverage.

1. **Inputs and entry points:** exported functions, input readers, callbacks that deliver data, command-line and environment access, file and message parsers, and who can call each of them.
2. **State, secrets and authorization:** global and context state, secrets and where they are released, authorization and validation decisions with the state they set, initialization and teardown order, locks.
3. **Outputs and platform:** every place where data leaves the target (sockets, files, logs, the terminal, IPC, out-buffers, callbacks that hand data out), process and filesystem effects, and the build or configuration switches that add or remove any of the above.

For an additional pass, choose a lens from the open questions or the unknowns of `Context.md` and record it in the ledger before assigning files.

## Row kinds

Every row carries an ID, the function as `name` or `file#name`, the exact source reference (`path:line-line`), and one sentence saying what the code does there. A row states what the source shows; mark anything else `inferred`, with the reason.

| Kind | ID | What to record |
| --- | --- | --- |
| Entry point | `EP-NNN` | A function that receives data from outside the target: its prototype, which parameters carry that data, which carry a length, and who calls it (external code, a callback registration, `main`). |
| Reader | `RD-NNN` | A function that returns or fills outside data for its caller, like `read(2)`: the buffer and length parameters, and whether it is the target's own, a callback type, or external. |
| Sink | `SK-NNN` | A function through which data leaves the target: its kind (network, file, log, terminal, ipc, buffer, other), the data, length and format parameters, and whether it transmits itself or forwards to another function. |
| Secret | `SE-NNN` | A value that must not leak: where it is held (global, parameter, field, local, return value), its size, the functions that read and write it, and the function that releases or wipes it. |
| Authorization gate | `AG-NNN` | A check that must pass before something privileged runs: the gate function, the state it sets, its success value, and the functions it protects. |
| State | `ST-NNN` | Mutable state that other properties depend on: a global or context field, the functions that write it, the functions that read it, the condition that always holds for it, and any required call order (initialization before use, a lock held at a call). |
| Trusted-only caller restriction | `TC-NNN` | Evidence that a function is called only by trusted code: an internal header, a `static` linkage, documentation of an internal API, or a call graph confined to the target. |

Record a sink that forwards (a wrapper that passes its buffer on to a backend) and the function that finally transmits as two rows, and say in each which one it is. The property is checked where the data is complete, so the model needs to know which function that is.

## Search probes

Reading the files is the method. The probes below are a cross-check afterwards: run each one over the scope and make sure every hit is covered by a row or by a negative result. A probe with no hit is a negative result worth recording.

- **Readers:** `read`, `recv`, `recvfrom`, `recvmsg`, `fread`, `fgets`, `fgetc`, `getc`, `getline`, `scanf` and relatives, `getenv`, `accept`, `mmap` of a file, and every function pointer type whose implementation fills a buffer.
- **Entry points:** every function declared in a public header or exported by the build; `main`; functions registered as callbacks or stored in dispatch tables; signal handlers.
- **Sinks:** `write`, `send`, `sendto`, `sendmsg`, `fwrite`, `fputs`, `fputc`, `puts`, `printf` and relatives, `syslog`, `vsyslog`, `perror`, and every function pointer type whose implementation receives a buffer to emit.
- **Secrets:** identifiers containing `key`, `secret`, `passw`, `token`, `nonce`, `seed`, `priv`, `cred`, `salt`; calls of `memset`, `explicit_bzero`, `memset_s` and library wipe functions on such objects; comparisons with `memcmp` or a constant-time equivalent.
- **Authorization:** identifiers containing `auth`, `login`, `verify`, `check`, `perm`, `priv`, `allow`, `deny`, `session`; early returns that depend on a credential comparison.
- **State and order:** file-scope and `extern` variables that are written, `init`/`open`/`create` functions paired with `free`/`close`/`destroy`, `pthread_mutex_lock` and other lock calls, flags tested before use.
- **Configuration:** `#if`, `#ifdef` and build options that add or remove an entry point, a reader, a sink or a check.

A name match is never a row by itself. Read the code at the hit, then record a row, a negative result, or nothing when the hit is unrelated (say so once per probe).

Save the outcome as `evidence/inventory/probes.md`, one line per probe family, so that "searched, none" can be told from "not searched":

```markdown
| Probe family | Patterns searched | Hits | Covered by rows | Negative result or reason |
| --- | --- | --- | --- | --- |
```

Then work two of the families backwards, because a forward read misses what it never reaches:

- **From each sink, upward.** List the callers of every sink and follow them until an entry point, a reader, or a function nothing calls. A sink whose callers end at a function that is not in the inventory has found a missing entry point.
- **From each secret and state row, sideways.** List every function that reads or writes the object, not only the ones the first pass met. They become the reader and writer sets of the row.

Record what the source hides from a plain read, as rows of kind `inferred` or as questions: tables of function pointers and the functions stored in them, callbacks registered at run time, functions generated by macros, symbols loaded dynamically, and code that exists only under a build option. The verification resolves indirect calls less well than direct ones, so each of these is worth a line.

## Partition and dispatch

- Partition the canonical inventory (`files.txt`) deterministically and keep assignments disjoint within a pass.
- Use up to six workers per pass when delegation is supported, unless the request names another number. Never require delegation for correctness.
- Give a worker only the confirmed scope, its assigned paths, the pass lens, the row kinds, the facts of `Context.md` it needs, and the output contract below.
- Do not give a worker another worker's rows, a previous threat model of the target, or any pipeline result.
- Require the worker to read each assigned eligible file completely enough to issue a receipt.
- Prohibit source edits, command execution in the target, service startup, external requests, and nested delegation.

When delegation is unavailable, process the same deterministic assignments sequentially, keep pass notes separate, and record that worker independence was not available.

## Complete assignment result

Require one self-contained Markdown result in this shape:

```markdown
# Pass N Result — worker-NN

## Coverage

| Path | Status | Notes |
| --- | --- | --- |
| `relative/path` | reviewed | What the file holds for this lens. |

## Rows

| ID | Kind | Function | Source | Statement | Basis |
| --- | --- | --- | --- | --- | --- |
| worker-local ID | entry point | `file#name` | `path:line-line` | One sentence. | observed or inferred, with the reason |

## Negative Results

- Surface checked, and why no row remains (for example: "no file in this assignment writes to a socket, a file or a log").

## Questions

- A fact the source cannot settle (deployment, who calls an exported function), and which rows depend on it.
```

If no row remains, write `No rows.` under `## Rows`. Do not omit any top-level section.

Allowed coverage states are:

- `reviewed`: the file was read for this lens;
- `not-applicable`: the file holds nothing this lens looks for, with a reason;
- `deferred`: a concrete unreadable format, missing dependency, or unresolved cross-file question prevents a receipt, with the exact reason.

## Register receipts

Save the entire assignment result below `evidence/inventory/pass-N/`; never reconstruct only its coverage table. Verify that:

- every assigned path appears exactly once;
- no unassigned path appears;
- every status is allowed;
- every deferred row has a reason;
- every row has a function, a source reference and a basis;
- the negative-results and questions sections are intact.

Then give the rows their final IDs, merge rows that describe the same function and role (keep every source reference), run the search probes, and fill "Inventory Counts" in the ledger. Move the workers' questions to "Open Questions".

Close the phase only after every assignment in every pass has a valid receipt and every probe hit is accounted for. Treat deferred files, missing results, reduced requested capacity, and incomplete pass coverage as explicit gaps.
