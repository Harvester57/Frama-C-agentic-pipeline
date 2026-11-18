# Target Context

Understand what the target is before listing what can go wrong with it. Write `Context.md` from the documentation first, then from the build files and the source layout. It answers the first threat-model question ("what is being built?") and gives the later phases, and the Frama-C pipeline's Phase 0, the facts no parser derives.

Keep it short. A section with nothing to say holds one sentence saying what was looked at; never fill a section to make it look complete.

## Sources, in this order

1. `README`, design notes, manual pages, protocol or format specifications, and security policy files in the scope. Summarize the stated purpose before reading any source file.
2. Build files, read and never executed: `Makefile`, `CMakeLists.txt`, `configure.ac`, `Makefile.am`, `meson.build`, `*.pc.in`, `config.h.in`, and CI definitions, which usually hold the real build and test commands.
3. The directory tree and the public headers.
4. Source files, only as far as a claim below needs one.

Do not look up the target's known vulnerabilities, advisories or bug trackers, and do not read results of an earlier analysis of the target, unless the user supplies them for this review. The model must come from the source, so that the verification it feeds stays independent of what is already known.

## Evidence rules

- Every claim cites the path (and line, for source) it comes from.
- A claim the files do not settle is marked `[UNKNOWN]` when a later phase may settle it, and `[ASK USER]` when only the user can (deployment, who links the library, which configuration ships). Each `[ASK USER]` item also goes to "Open Questions" in the ledger.
- A claim deduced rather than read is marked `inferred`, with the reason.

## `Context.md` contract

Preserve these sections:

```markdown
# Target Context — REVIEW_ID

## Purpose

What the target does, for whom, and what it processes, in a few sentences, with the documents that say so.

## Deployment

| Shape | Who runs it, with what privileges | Who supplies its input | Source |
| --- | --- | --- | --- |

A library has one row per way it is embedded (linked into a network daemon, a command-line tool, firmware).

## Directory Roles

| Path | Role | Reason | In scope |
| --- | --- | --- | --- |

Roles: product, public header, test, example, fuzz target, vendored, generated, build support, documentation.

## Build And Test

| Fact | Value | Source |
| --- | --- | --- |
| Build system | | |
| Build command, as documented | | |
| Packages or libraries it needs | | |
| Test command, as documented | | |
| Fuzz targets or corpora shipped | | |

These are proposals read from the files. Nothing here was executed.

## Build Options And The Attack Surface

| Option or macro | Default | What it adds or removes | Source |
| --- | --- | --- | --- |

List only switches that add or remove an entry point, a reader, a sink, a check or a secret. State which configuration the rest of the review assumes.

## External Interfaces

| Interface | Direction | Peer | Trust of the peer | Source |
| --- | --- | --- | --- | --- |

Network protocols, file formats, IPC, environment, command line, callbacks the embedder supplies, libraries called.

## Open Questions

Numbered `[ASK USER]` items, each with the sections it affects and the assumption used until it is answered.
```

## Use by the Frama-C pipeline

`Context.md` is prose for people and for the later phases of this review. The pipeline does not read it, and its own captured build and parsed model win wherever they disagree with it.

Three of its tables help the pipeline's Phase 0, always through the user:

- **Build And Test** gives the build command, the packages and the test command to propose when Phase 0 asks for the build recipe. Phase 0 records only a recipe the user gave or confirmed.
- **Directory Roles** tells which link units are tests, examples or vendored code when the trust boundary and the scope are reviewed.
- **Build Options And The Attack Surface** tells which configuration the threat model describes. A run that builds another configuration needs the model reviewed again.

State these three uses in the hand-off.

## Exit gate

Close the phase only when:

- the purpose and at least one deployment shape are stated with their source, or marked `[ASK USER]`;
- every top-level directory of the scope has a role;
- the assumed build configuration is named;
- every `[ASK USER]` item is in the ledger.

Ask the open questions once, together, when the phase closes. Continue with the stated assumptions if the user is not available, and keep the questions open in the ledger.
