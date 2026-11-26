# Schema-driven and stream APIs in the `--api` harness

- **Why:** on a library that decodes or encodes bytes under a build-time schema (a generated
  descriptor, a type table, an ops table), the `--api` harness fills the trusted schema from the
  fuzz input and leaves the attacker's byte stream empty. Phase 1 then finds crashes the API
  contract excludes, Eva turns most of the codec Dead, and the target's own corpora feed no case.
- **Evidence:** nanopb run-1 (2026-11-20, standard profile, module `libprotobuf_nanopb_a`),
  Section 2. Measured from the run's artifacts by the run supervisor, read only.
- **Found:** 2026-11-20, while supervising nanopb run-1
  ([`../runs/2026-11-20-nanopb-run1-supervision.md`](../../runs/2026-11-20-nanopb-run1-supervision.md)).
- **Status:** proposal, not implemented. Nothing here was changed while the run was going.

## 1. The pattern

Many C codecs have the same three kinds of argument:

| Kind | nanopb | Who controls it | What the harness should do |
| :--- | :--- | :--- | :--- |
| Schema | `const pb_msgdesc_t *fields`, `pb_extension_type_t` | The developer, through a generator (`nanopb_generator.py` writes `*_msg` descriptors into `.pb.c`) | Use real instances. Never fill it from fuzz bytes |
| Stream or state object | `pb_istream_t`, `pb_ostream_t` (a `callback` pointer, `state`, `bytes_left` / `max_size`) | The developer builds it, usually with a library builder (`pb_istream_from_buffer`) | Build it with the builder. Give the builder the fuzz bytes |
| Attacker data | the bytes behind the stream; the untrusted fields of `src_struct` | The peer | Fill from the fuzz input |

The same split occurs in protobuf-c (`ProtobufCMessageDescriptor` globals in `.pb-c.c`), upb
(`upb_MiniTable`), asn1c (`asn_DEF_*` type descriptors), CBOR or JSON libraries driven by a schema
table, and in libraries with const ops or info tables (mbedTLS `mbedtls_cipher_info_t`,
`mbedtls_md_info_t`). nanopb states the split itself in `docs/security.md:20-43`, and the reviewed
threat model of run-1 adopts it.

## 2. Evidence from nanopb run-1

The threat model (`.security-reviews/20261120T174556Z-nogit/ThreatModel.md`, SHA-256
`024e264f...`) lists in `input_sources` which parameters carry attacker data: for `pb_decode`
only `stream`, for `pb_encode` only `src_struct`, and for each reader the stream it reads. The
harness does not read the threat model: `scripts/api_harness.py` has no reference to trust,
the threat model or `input_sources`.

Measured on `workspace/harnesses/harness_libprotobuf_nanopb_a.json` (36 cases, one per exported
function), comparing the parameters each case fills from the input with the threat model. The
rows overlap: a case can leave an attacker parameter unfed and fill a trusted one (`pb_decode`).

| Measure | Cases | Examples |
| :--- | ---: | :--- |
| A parameter that carries attacker data gets no input byte (for a reader: its stream) | 25 | `pb_decode(stream)`, `pb_decode_varint(stream)`, `pb_read(stream)`, `pb_encode(src_struct)` |
| A trusted parameter is filled from the input | 11 | `pb_decode(fields)`, `pb_encode(fields)`, `pb_field_iter_begin(desc)`, `pb_istream_from_buffer(msglen)` |
| Matches the threat model | 6 | `pb_write`, `pb_encode_string`, `pb_encode_varint`, ... |
| Function has no `input_sources` entry (no attacker data) but a case | 3 | `pb_field_iter_begin_extension(_const)`, `pb_ostream_from_buffer` |

Case 9 (`pb_decode`) as generated: the stream is `memset` to zero (`callback` NULL,
`bytes_left` 0), so the decoder reads no byte at all. The fuzz bytes go to the descriptor's
`field_count`, `required_field_count` and `largest_tag`, over zeroed `field_info` /
`submsg_info` / `default_value` arrays. Every reader case (`pb_decode_varint`,
`pb_decode_fixed32`, `pb_read`, ...) also gets a zeroed stream.

The consequences in the run:

| Phase | Result | Cause |
| :--- | :--- | :--- |
| Phase 1 | 25 crash artifacts at 5 sites (`load_descriptor_values` `pb_common.c:17`, `advance_iterator` `:126`, `pb_field_iter_begin_extension` `:168`, `pb_field_iter_find` `:201`, `safe_read_bool` `pb_encode.c:130`). By dispatch case (the identity selector is the first input byte): **10** from a trusted descriptor filled from the input (`pb_decode` 2, `pb_decode_ex` 4, `pb_encode_ex` 4); **10** from a zeroed `iter`, an attacker parameter that holds a trusted descriptor pointer (`pb_field_iter_find` 5, `pb_field_iter_find_extension` 2, `pb_field_iter_next` 3); **5** from functions without attacker data (`pb_field_iter_begin_extension` 3, `_const` 2) | NULL or garbage descriptors and extension types: a violation of the API contract, which the Crash Verifiers must reject one by one |
| Phase 2 | 783 properties, 98.34% discharged, but 1844 obligations Dead; non-terminating statements at `pb_common.c:126`, `:168`, `:201`. Dead by function: harness 534, `load_descriptor_values` 135, `decode_static_field` 127, `pb_field_set_to_default` 76, `pb_dec_varint` 75, `encode_array` 72, ... | Every path stops at the NULL descriptor accesses, so the decoder and encoder proper are never analysed. The ledger handles it correctly (Dead never counts as proof), but Eva contributes almost nothing for the codec |
| Phase 0 / 1 | The shipped fuzzer `tests/fuzztest/fuzztest.c` is not built, and the mapped corpora (3670 + 7 + 2 inputs) feed no case (`seeds.writers.fuzz_assets`: "no imported corpus feeds a harness case that takes the whole input") | The corpora are whole messages for the `AllTypes` descriptors, which only the generator makes, and the recipe builds with `-Dnanopb_BUILD_GENERATOR=OFF`. Open entry in [`../troubleshooting/harnesses-and-seeds.md`](../../troubleshooting/harnesses-and-seeds.md) ("A Shipped Fuzzer ... Cannot Feed the Run (nanopb)") |
| Phase 0 | `global_variables` in the model is empty | The runtime defines no descriptor. Instances exist only in generated sources |

## 3. What exists already

| Mechanism | Where | Use here |
| :--- | :--- | :--- |
| `input_sources[].params` (attacker parameters per entry) and `role: reader` | `schemas/threat_model.schema.json`, threat-model skill | The input of S1. Already filled by the threat-model skill; nothing reads it at harness time |
| `trusted_callers` (functions only trusted code calls; preconditions may constrain values) | same schema | Per function, not per parameter. S5 needs the per-parameter form |
| Struct initializers called before every case that takes the struct (`initializers()`, supervisor S10, `e70ede5` / `2fcd947`): a function named like an initializer (`_INIT_NAME_RE`: `*_init`, `*_new`, `*_create`, `*Init`) whose first parameter is a non-const pointer to the struct, preferring one that reads a (buffer, length) pair from the input. Entry "`--api` Cases Pass an All-Zero Context Struct" in [`../troubleshooting/harnesses-and-seeds.md`](../../troubleshooting/harnesses-and-seeds.md) | `scripts/api_harness.py` | The right mechanism, but nanopb's builders miss its rule: `pb_istream_from_buffer` returns the stream by value and is named `*_from_*`; `pb_field_iter_begin` is named `*_begin`. S2 widens it |
| Opaque-handle constructors (`handle_functions`) and out-parameter constructors (`outparam_constructors`) | `scripts/api_harness.py` | Same name rule; handles only |
| Argument-domain rules A to F (supervisor S14, `08113dc` and following) and the open gaps G, H, I ("Most `--api` Crashes on a Library Come From Argument Values the API Documents as Invalid", same troubleshooting file) | `scripts/api_harness.py` | Gap H (fabricated internal objects) is the same family as SD1b; S1 and S2 cover the schema case of it |
| Per-case Eva shards (`FRAMAC_EVA_SHARD_CASE_<k>`) | generated harness | S4: one case per schema instance gives per-instance Eva for free |
| Corpus mapping to a case that takes the whole input | `scripts/fuzz_assets.py` (`map`, `import`) | S3: the shipped corpora feed the new "message for instance X" cases |
| Shipped fuzzer skipped when it needs code outside the unit | Phase 0 skill (`skills/framac-slice/SKILL.md`) | S3 makes the generated sources part of the unit, so the rule no longer bites |
| `harness_induced` rejection and its precondition | [`./harness-and-spec-papers-generalization-plan.md`](./harness-and-spec-papers-generalization-plan.md), Tier 1 | S1 removes most of these candidates at the source instead of rejecting them later |
| Program harnesses | [`./fuzz-budget-design.md`](../fuzz-budget-design.md), P8 | An alternative for targets with a shipped fuzzer; S3 is the narrower route |

## 4. Decisions

| # | Question | Proposal |
| :--- | :--- | :--- |
| SD1 | What marks a parameter as trusted? | A parameter of an `input_sources` entry with `role: entry` that is not in its `params`. A reader (`role: reader`) returns or fills attacker data, so its case needs a source object that carries input bytes (nanopb: the stream) and gives its output parameters plain buffers; the schema has no field that names that source parameter today, so S1 takes it from S2's builders (the parameter whose type a builder makes from bytes) and otherwise keeps today's behaviour. A function with no `input_sources` entry carries no attacker data. Without a threat model, or for an entry without `params`, the harness keeps today's behaviour (every parameter from the input). |
| SD1b | An attacker struct that holds trusted members (`pb_field_iter_t`: trusted `descriptor`, attacker `message`; `src_struct` of `pb_encode`: trusted callbacks, pointer fields with their `_count`, extensions). | Parameter-level trust is too coarse for these. Such an object is built by the library's builder from a schema instance (`pb_field_iter_begin(&iter, &X_msg, msg)`, S2), never filled field by field. For a struct the threat model describes as partly trusted (`src_struct`), the case decodes first and encodes the result (decode-then-encode), or zeroes the trusted members; filling them from the input recreates harness-induced crashes. |
| SD2 | What does the harness put in a trusted pointer parameter? | In order: (a) a schema instance (S3) of the pointee type; (b) the result of a builder (S2); (c) none: the case is not generated, and the static reach gate records the function as exempt with the reason "trusted parameter `<name>` has no instance". It never falls back to fuzz bytes. A zeroed object is not an instance. |
| SD3 | Functions with no attacker data (`pb_ostream_from_buffer`, `pb_field_iter_begin_extension`). | No fuzz case. Exempt from the static reach gate with the reason "no attacker data per the threat model". They stay in the ledger for WP. |
| SD4 | Where do schema instances come from? | Const globals of the parameter's pointee type in the unit's sources, from the Phase 0 model (`global_variables` needs the type, `const`, and the file). Generated sources count when the recipe produces them (SD5). |
| SD5 | Should the recipe run the target's generator? | **Open, for the user.** For nanopb: run `nanopb_generator` on the `.proto` files the target ships for its tests (`tests/alltypes/alltypes.proto` covers every field type) and record the `.pb.c` / `.pb.h` as generated sources of the unit. This is a recipe change the user confirms, like any recipe. |
| SD6 | One case per instance, or a selector inside one case? | One case per (entry, instance), capped (default 4 instances per entry, the ones with the most fields first). This reuses the per-case Eva shards and the per-case seed and corpus mapping. |
| SD7 | WP. | Schema instances are for fuzzing and Eva only. A WP proof must hold for every valid schema, so a trusted parameter gets a well-formedness precondition instead (S5). |

## 5. Steps

Per the run rules, each step runs the unit suite only; one real-target validation (nanopb,
then one more target from Section 6) closes the plan.

### Step 0: measure, no code (stop rule)

Write `tools/harness_trust_census.py` (read only): for a finished run with a threat model, the
table of Section 2 (attacker parameters without input bytes, trusted parameters filled from the
input, functions without attacker data that have a case), plus the share of crash candidates whose
faulting access lies in an object reached only through a trusted parameter, and Eva's Dead count by
function. Run it on nanopb run-1 and on every earlier run whose model records a threat model
(`trust.threat_model.status: ok`) and kept its harness sidecars; if there is none, on the next
such run.

- **Stop** if, outside nanopb, no case fills a trusted parameter from the input and no attacker
  parameter goes unfed: then the problem is nanopb's alone, and S3 alone (the generated sources)
  is worth doing.
- **Go** with S1 and S2 if at least one other target shows either mismatch.
- The census also says why the `pb_istream_s` parameter got no slot at all (a struct with a
  function-pointer field, or the layout probe). S2 depends on that answer.

### S1: fill only the attacker parameters (SD1, SD2, SD3)

- **Change:** `scripts/api_harness.py` reads the threat model through the model's `trust` block
  (path and SHA-256 already recorded there) and gives each parameter a role: attacker, trusted or
  output. Attacker parameters are filled as today. Trusted parameters follow SD2. Functions without
  attacker data get no case and an exemption with a reason. `scripts/harness_reach.py` accepts
  the two new exemption reasons.
- **Tests:** a fixture library with `decode(stream, desc, out)` and a threat model naming only
  `stream`: no slot on `desc`; without a threat model, today's slots; a function without an entry
  gets no case and a recorded exemption.
- **Value:** removes 15 of nanopb's 25 artifacts at the source (the 10 from a fuzzed descriptor
  and the 5 from functions without attacker data), and stops spending the fuzz budget on the
  schema. The other 10 (zeroed `iter`) need S2's schema-instance builders (SD1b): filling `iter`
  from the input would put fuzz bytes behind its trusted `descriptor` pointer and keep them.
- **Risk:** a wrong or incomplete threat model hides attacker data. Mitigations: SD1 keeps
  today's behaviour when `params` is absent, and the census of Step 0 runs at the end of Phase 0
  as a warning (a trusted parameter that is written through, or an attacker parameter of a type
  with no builder).
- **Cost:** medium.

### S2: build stream and state objects with the library's builder

- **Change:** widen `initializers()` in `api_harness.py` (S10) on two axes: a builder may
  return the struct by value (`pb_istream_t pb_istream_from_buffer(const pb_byte_t *, size_t)`) as
  well as fill it through its first parameter, and the name rule also accepts `*_from_*` and
  `*_begin*` when the function's type relation is unambiguous (it returns or fills exactly the
  struct the case needs). S10's preference for a (buffer, length) pair the call only reads stays,
  so the case calls the builder with the rest of the input
  (`pb_istream_from_buffer(fuzz_buf + off, fuzz_len - off)`) and passes the result to the entry.
  The builder installs the real callback (`buf_read`), so Eva sees the one callee instead of the
  type-match set.
- **Also:** builders that take a schema instance instead of bytes (SD1b): an object of a type
  some API function initializes from a schema pointer (`pb_field_iter_begin(iter, desc, message)`)
  is built by that function with an instance from S3 and a message buffer, then passed to the
  entry (`pb_field_iter_find`, `pb_field_iter_next`, `pb_field_iter_find_extension`). Without an
  instance, SD2(c) applies.
- **Tests:** a fixture stream struct with a callback field and a `*_from_buffer` builder: the case
  calls the builder; without a builder, the attacker parameter is filled by layout as today.
- **Value:** the readers (`pb_decode_varint`, `pb_read`, `pb_decode_tag`, ...) and `pb_decode`
  receive bytes for the first time.
- **Risk:** a builder with side effects (allocation, a file). Reuse the existing filters
  (`path_parameter`, destructors from `handle_functions`).
- **Cost:** medium.

### S3: schema instances from the unit and its generated sources (SD4, SD5)

- **Change:** `phase0_model.py` records const globals with their type and file in
  `global_variables`. `build_capture.py` records generated sources the recipe produces (the
  `.pb.c` files) as sources of the unit when they are compiled into a test or an example the
  recipe builds, or when the recipe names them. `api_harness.py` takes the instances of a trusted
  parameter's pointee type (SD6 cap) and generates one case per instance, with the attacker data
  built as in S2 and an output buffer of `sizeof` the message type the generator pairs with the
  descriptor (nanopb: `<Msg>_msg` with `<Msg>`).
- **Tests:** a fixture with two generated descriptors: two cases, each naming its instance; no
  instance gives the SD2(c) exemption.
- **Value:** the codec is exercised on real schemas. The shipped corpora (whole `AllTypes`
  messages) map to the `pb_decode(..., &AllTypes_msg, ...)` cases. A `tf_fuzztest` module for
  `fuzztest_proto2_static` / `fuzztest_proto3_static` (the configurations without
  `PB_ENABLE_MALLOC`) also needs the test helpers `fuzztest.c` includes (`random_data.c`,
  `validation.c`, `flakystream.c`) as sources: a second recipe question for SD5.
- **Risk:** coverage narrows to the shipped schemas. A bug that needs a valid but unusual schema
  is missed by fuzzing and Eva. S5 covers it in WP.
- **Cost:** medium to large (model, capture and harness).

### S4: Eva per instance

- **Change:** none beyond S3 if SD6 holds and the harness's `FRAMAC_EVA_SHARD_CASE_<k>` guards
  are used: each instance is then its own case, analysed apart. **To check first:** nanopb run-1's
  Eva ran one `eva_main` over all 36 cases (one report, 46 s), so whether and when Eva shards per
  case must be read from `run_eva_slice.py` and `pipeline_make.py` before relying on it. Also check
  that eva-tune and the guard treat the new cases like the old ones.
- **Value:** with a concrete descriptor, Eva's state stays precise. The Dead count of Section 2
  should fall to the parts of the codec the instances do not use.
- **Cost:** small (tests and the end measurement).

### S5: WP precondition for trusted parameters (SD7)

- **Change:** the per-parameter trust of S1 reaches the prover brief: a trusted parameter may get
  a `requires` that states its well-formedness, written by the prover as a predicate, and the
  verifier does not count it as a weakened contract. For nanopb this is a predicate over
  `pb_msgdesc_t` (field count and the `field_info` words), which is real work for the prover.
- **Value:** proofs that hold for every valid schema, not only the instances.
- **Risk:** a predicate strong enough to make everything provable. The verifier keeps the rule that
  the predicate must hold on every instance S3 found (checked with Eva or by evaluating the
  predicate on the instances).
- **Cost:** large. Depends on S1. Can be dropped if the end validation shows WP already proves
  the codec under the existing `trusted_callers` form.

### S6: troubleshooting and skills

- Close or update the two open nanopb entries in
  [`../troubleshooting/harnesses-and-seeds.md`](../../troubleshooting/harnesses-and-seeds.md).
- Describe the parameter roles in the Phase 0 and Phase 1 skills, and in the threat-model skill:
  the reviewer must check `params` on every entry, since the harness now depends on it.

## 6. Transfer

Only the nanopb row is checked against a run; the other rows are from knowledge of those libraries
and must be confirmed on their sources before a validation run.

| Target | Schema | Instances | Builder |
| :--- | :--- | :--- | :--- |
| nanopb | `pb_msgdesc_t` | generated `*_msg` (needs SD5) | `pb_istream_from_buffer`, `pb_ostream_from_buffer` |
| protobuf-c | `ProtobufCMessageDescriptor` | generated `*__descriptor` in `.pb-c.c` | none: the API takes `(len, data)` directly, so S1 and S3 suffice |
| asn1c output | `asn_TYPE_descriptor_t` | generated `asn_DEF_*` | none: `ber_decode(ctx, &asn_DEF_X, &ptr, buf, len)` |
| mbedTLS | `mbedtls_cipher_info_t`, `mbedtls_md_info_t` | const tables in the library itself (no generator) | `*_setup` with an info pointer |

The mbedTLS row needs no recipe change: S1 and S3 alone apply, because the instances are in the
library's own sources.

## 7. Order and validation

Step 0, then S1 and S2 (independent files inside `api_harness.py`: one fixer at a time), then S3,
S4, and S5 last. End validation: a new nanopb run with the same threat model and, if the user
confirms SD5, the generator in the recipe. Acceptance:
- none of the 25 harness-induced crash shapes of Section 2 recurs (a fuzzed descriptor, a zeroed
  or input-filled iterator, a case for a function without attacker data);
- every reader case and `pb_decode` receive input bytes through a built stream;
- Eva's Dead count on the codec functions of Section 2 at least halved;
- the shipped corpora feed at least one case.
