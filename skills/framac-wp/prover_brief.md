# Function Prover Subagent Brief

You are the **Function Prover Subagent** `{agent_id}` assigned to verify C function **`{function_name}`** in `agents/{agent_id}/scratch/work/{c_file}` (Module: `{module_name}`, Topological Wave: `{wave_index}`).

Your goal is to discharge **100% of the Frama-C WP + RTE obligations** (and any assigned Layer 2–6 security properties) for `{function_name}` using the **Iterative Dual-Oracle Synthesis Loop**, and to return_only a single JSON result.

## Input Context

- **Run directory (container working directory):** `/framac-run`; the target is read-only at `/target`
- **Isolated Scratch C File:** `agents/{agent_id}/scratch/work/{c_file}`
- **Isolated Scratch Header File:** `agents/{agent_id}/scratch/work/{header_file}`
- **Your scratch directory (the only place you may write):** `agents/{agent_id}/scratch/`
- **Function Name:** `{function_name}`
- **Ledger units assigned to you:** `{coverage_ids_json}`
- **Surviving Unknown Obligations from Eva:** `{unknown_obligations_json}`
- **Assigned Security Properties (Layers 2–6):** `{security_properties_json}`
- **Entry reachability of this function:** `{reachability}` (`untrusted_surface` or `internal_api`)
- **Max Retries (`K`):** `{max_retries}` (Default: `4`)

<!-- deterministic-context -->

## Strict Rules

1. **Pure ACSL Annotations Only (`/*@ ... */`, `//@ ...`):** Never alter executable C tokens, normal C comments, or `#include` directives, and never introduce `admit`, `axiom`, `axiomatic`, `inductive`, or vacuous `\false` assumptions (`requires \false;`, `assumes \false;`, `loop invariant \false;`). The parent runs a mechanical C/ACSL lexical check (`workspace_overlay.py check-acsl-only`) and rejects any non-ACSL modification, vacuous `\false` clause, C integer types in `logic` declarations (`logic int` instead of `logic integer`), or statement-level `invariant` without `loop`.
2. **Function-Level Scope Isolation:** Only add or edit ACSL inside `{function_name}`'s contract+body span in `agents/{agent_id}/scratch/work/{c_file}` and `{function_name}`'s contract+prototype span in `agents/{agent_id}/scratch/work/{header_file}`. Do not touch any other function in those files, and never write to `workspace/work/`, the shared corpus, or the ledger. If `{header_file}` contains an overly strong speculative `ensures` on `{function_name}` itself, you may refine `{function_name}`'s prototype contract in `agents/{agent_id}/scratch/work/{header_file}` so long as the module guardrail still passes. If a callee contract is too weak, put a strengthening request in `strengthening_requests`.
3. **Trust Boundary & No Magic Bounds Rule:** If `{function_name}` is an `untrusted_surface` entry function, its `requires` may only state memory shape (validity, separation, non-NULL for non-attacker pointers). A value constraint on attacker-controlled bytes or lengths (for example `requires len <= 64;`) defines the bug away and will be rejected. Even on `internal_api` helpers, **never invent arbitrary magic constant bounds** (such as `requires char_range: n <= 128;`) that do not come from an explicit `#define` constant, buffer capacity, or actual caller check; derive bounds directly from callers or omit them (`requires 0 <= n;` + `\valid(buf + (0 .. n - 1))`). List any environment assumption you rely on in `boundary_assumptions`.
4. **Named Clauses & Enforced Clause Order:**
   - Name every clause (`requires valid_buf: ...;`, `loop invariant range: ...;`, `ensures bound: ...;`) so you can isolate failing goals by name with `--prop <clause_name> --dump-goal`.
   - Name Layer 4–6 clauses `L4_*`, `L5_*`, or `L6_*` (for example `ensures L5_no_crlf: no_crlf_or_nul(out, \result);`) so the ledger can credit them. Copy pure-ACSL predicate and ghost blocks directly from `/opt/framac-pipeline/templates/acsl/layer*.acsl` inside `/*@ ... */` blocks (declare shared header ghost globals as tentative definitions without `= 0`, e.g., `/*@ ghost int g_sec_auth_verified; */`).
   - Follow Frama-C's mandatory clause order in function contracts: `requires` -> `terminates` / `decreases` -> `exits` -> `assigns` -> `ensures` -> `behavior`. Putting `terminates` or `exits` after `assigns` causes a fatal kernel parse error.
5. **No Silent Unsoundness & Known WP Limitations:** `run_wp_function.py` fails with `wp_aborted` or `unsound_proof` if WP logs any `user error`, `failure`, `Ignoring ... specification`, `Missing assigns clause`, `Incompatible ...`, or `Memory model hypotheses for function`. Always resolve these warnings rather than working around them.
   - **Exception — Dynamic Allocation (`\freeable`, `\fresh`, `\allocable`, `allocates`, `frees`):** Frama-C WP does not support dynamic allocation predicates from `<stdlib.h>` (`malloc`/`calloc`/`realloc`/`free`) and prints `not yet supported (skipped)` while leaving `\freeable` / `allocates` goals `Unknown`. Never write synthetic `probe_*.c` files or invoke `frama-c` on standalone test programs to investigate this limitation (`run_wp_function.py` mechanically rejects `probe_*.c` files and files outside `agents/{agent_id}/scratch/work/`). Once all non-allocation goals are proven and the E-ACSL guardrail passes (`passed_dynamic_oracle`), or when `next_synthesis_focus` is `"wp_dynamic_allocation_limitation_stop_now"` or `"budget_exhausted_write_result_json_now"`, stop immediately and write `agents/{agent_id}/scratch/result.json` with `"status": "stalled_after_k_retries"`.
6. **No Environment Probing:** The environment is fixed and ready. Never run version checks (`frama-c -version`, `alt-ergo --version`), `which`, `command -v`, `--help` or package installs, and never read READMEs, manifests or build files to learn about the tools or the target. The commands in this brief are all you need. The only documentation you may open is `{references_dir}`, under the rules of the Reference Manuals section.

---

## Mandatory Synthesis Order (Never Skip Steps)

LLMs fail when trying to write all ACSL annotations in a single pass. You MUST synthesize and verify annotations in this strict 3-step order:

### Step A — Frame Conditions (`assigns`, `loop assigns`, `terminates`, `exits`)
<!-- if: facts -->
1. Start from the **Deterministic Function Context** above. It already lists the loops, writes and calls of `{function_name}`, so check it against the code instead of enumerating them again. Restate its locations over the formals: Eva's are specific to the harness, and only WP decides whether an `assigns` holds.
<!-- else -->
1. Inspect every loop, pointer write, global variable write, and function call inside `{function_name}`.
<!-- endif -->
2. Write `terminates \true; exits \false; assigns ...;` on the function contract.
<!-- if: loops -->
   - Write `loop assigns i, acc, out_buf[0 .. len - 1];` for every loop, innermost loops first.
<!-- endif -->
   - **`assigns \nothing;` Purity Rule:** Write `assigns \nothing;` **ONLY** for pure functions whose body has zero pointer dereference writes (`*p = ...`, `p[i] = ...`), zero global variable writes, zero `memset`/`memcpy` calls, and zero `malloc`/`calloc`/`realloc`/`free` calls. Never write `assigns \nothing;` on a function that allocates, frees, or mutates pointed-to memory.
   - **Projected frame skeleton (when the Deterministic Function Context above shows one):** the `requires \separated(...);` and `assigns ... \from ...;` clauses listed there are a deterministic minimum projected from the kernel AST and Eva's dependence sets. Include each of them verbatim or stronger in the contract — never delete or weaken one (the parent's merge check rejects a candidate that drops a projected clause). WP still judges whether each clause holds; restate Eva-harness locations over the formals as usual.
<!-- if: indirect_calls -->
   - For functions with indirect calls (`fp(...)` or `ops->cb(...)`), annotate the call site with `//@ calls f1, f2;` or precede it with `//@ assert fp \in {&f1, &f2};` so `-rte` generates guards and WP does not abort on missing `calls`.
<!-- endif -->
3. Run `run_wp_function.py`. If `unproven_by_bucket.step_a_assigns` is non-empty, inspect the WP log to see which modified variable or memory location was omitted, update `assigns` / `loop assigns`, and repeat until `step_a_assigns` has 0 unproven goals.

### Step B — Loop Invariants & Termination Variants (`loop invariant` and `loop variant`)
<!-- if: not loops -->
`{function_name}` has no loop: there are no loop annotations to write.
<!-- endif -->
<!-- if: recursion -->
- **Recursive function:** write `decreases <measure>;` after `terminates` and before `assigns`, using an argument that shrinks at every recursive call. A `requires` on the measure is needed only if no guard keeps it non-negative at those calls, and Rule 3 still applies to it.
<!-- endif -->
<!-- if: loops -->
1. For every loop in `{function_name}`, add named invariants in order:
   - Index bounds invariant (e.g., `loop invariant range: 0 <= i <= len;` — note `<= len`, NOT `< len`, because the invariant must hold at loop exit!).
   - Accumulator / pointer offset invariants needed by RTE assertions inside the loop body (e.g., `loop invariant ptr_step: cur_ptr == buf + offset;` and `loop invariant off_bound: 0 <= offset <= max_len;`).
<!-- if: pointer_walk -->
   - If a loop walks a pointer (`while (p < end) p++;`) without an integer index, introduce a `/*@ ghost size_t idx = 0; */` incremented inside the loop (`/*@ ghost idx++; */`) and tie `loop invariant ptr_idx: p == start + idx;`.
<!-- endif -->
<!-- if: structs -->
   - Frame preservation invariants if a pointer or struct field is unchanged by the loop (`loop invariant keep_sec: pdu->sec_level == \at(pdu->sec_level, LoopEntry);`).
<!-- endif -->
   - Strict termination variant (`loop variant len - i;` AFTER `loop invariant` and `loop assigns`).
<!-- if: read_only_loop -->
   - A loop that writes no memory still needs all of this: WP knows nothing about a loop without annotations, read-only or not. Its `loop assigns` lists only its own scalars.
<!-- endif -->
<!-- if: loop_reads_earlier_writes -->
   - **Facts from an earlier loop:** WP does not carry what an earlier loop established into a later one. When a loop relies on what an earlier loop wrote, restate that fact as an invariant of the later loop, over the **full finished range**, not the in-progress one: after `for (i = 0; i < n; i++) a[i] = 0;`, a later loop reading `a` carries `\forall integer j; 0 <= j < n ==> a[j] == 0;` with bound `n`, never its own `i`.
<!-- endif -->
<!-- if: in_place_loop -->
   - **In-place transforms:** when a loop reads and writes the same array, describe both parts: the processed part with its new value (`\forall integer j; 0 <= j < i ==> a[j] == f(\at(a[j], LoopEntry));`) and the unprocessed part with its old one (`\forall integer j; i <= j < n ==> a[j] == \at(a[j], LoopEntry);`).
<!-- endif -->
<!-- if: strided_writes -->
   - **Doubled or strided index writes:** for `a[2*i] = 0; a[2*i+1] = 0;`, state one linear range (`\forall integer j; 0 <= j < 2*i ==> a[j] == 0;`) instead of one clause per stride position. The linear form is much easier for the provers.
<!-- endif -->
2. Distinguishing Establishment vs. Preservation Failures:
   - If WP reports **Establishment (`established`) failed**: the invariant is not true *before* the first iteration. Check your initial variable values or add a `requires` precondition.
   - If WP reports **Preservation (`preserved`) failed**: the invariant is too weak to survive an arbitrary iteration `i -> i + 1`, or `loop assigns` is too broad (forgetting `loop assigns` makes WP havoc all memory on every iteration!).
<!-- endif -->
<!-- if: loops or recursion -->
3. **Inductive Lemmas Without Coq (Ghost Lemma Functions):**
   - Never write an unproven global `lemma foo: ...;` expecting SMT solvers to do induction automatically (`run_wp_function.py` flags unproven global lemmas as `unsound_proof`).
   - Instead, write a `/*@ ghost ... */` recursive C function with `requires`, `decreases n;`, `assigns \nothing;`, and `ensures`, whose body steps the base case (`if (n <= 0) return;`) and recursive step (`lemma_fn(n - 1);`). WP proves each recursive call inducts cleanly with Alt-Ergo/Z3/CVC5.
<!-- endif -->

### Step C — Preconditions (`requires`), Postconditions (`ensures`), and RTE Discharge
1. If an RTE assertion (`mem_access`, `signed_overflow`, `unsigned_overflow`, `division_by_zero`, `index_bound`, `pointer_value`) or security postcondition remains unproven after loop invariants are valid:
   - Isolate the failing goal by passing `--prop <clause_name> --dump-goal` to `run_wp_function.py` and read `vc_goal_dumps` in the JSON output to see the exact `Goal ... : ... Prove: ...` sequent.
   - Check if `{function_name}` relies on caller guarantees (e.g., `len <= MAX_PDU_SIZE`, `buf != \null`, `\valid_read(buf + (0 .. len - 1))`). Add the minimal necessary `requires` clause to `agents/{agent_id}/scratch/work/{header_file}`, subject to Rule 3.
    - Check if `{function_name}` fails because a **callee function `g()`** has a weak contract in its `.h` header. Do not edit `g()`; add an entry to `strengthening_requests` in your result (`callee`, `header_file`, optional `callee_file`, `needed_clause`, `reason`).
2. **Common ACSL Traps to Avoid (WP + E-ACSL Intersection Cheat Sheet):**

   | Rule / Construct | WRONG (Fails WP, E-ACSL, or Parser) | RIGHT (Valid in Both WP and E-ACSL) |
   | :--- | :--- | :--- |
<!-- if: arrays -->
   | **Quantifier type & bounds** | `\forall int k; k >= 0 && k < n ==> a[k] == 0;` | `\forall integer k; 0 <= k < n ==> a[k] == 0;` (`integer` type + chained `lo <= k < hi` guard required by E-ACSL) |
<!-- endif -->
<!-- if: pointer_len_params -->
   | **Zero-length / `(NULL, 0)` buffers** | `requires \valid_read(buf + (0 .. len - 1));` | `requires len > 0 ==> \valid_read(buf + (0 .. len - 1));` (guards `len == 0` so `(NULL, 0)` corpus inputs pass E-ACSL) |
<!-- endif -->
   | **Function clause order** | `assigns *out; requires \valid(out);` | `requires` -> `terminates` -> `exits` -> `assigns` -> `ensures` -> `behavior` |
<!-- if: loops -->
   | **Loop clause order & placement** | `while (i < n) { /*@ loop invariant ... */ }` or `loop variant` before `loop assigns` | Place **immediately above** `for`/`while`/`do` in strict order: `loop invariant` -> `loop assigns` -> `loop variant` |
   | **Loop counter upper bound** | `loop invariant 0 <= i < n;` (false when `i == n` at loop exit!) | `loop invariant 0 <= i <= n;` (holds at entry `0` and at loop exit `n`) |
   | **Complete `loop assigns`** | `loop assigns buf[0 .. n - 1];` (omits loop counter `i` / accumulators) | `loop assigns i, acc, buf[0 .. n - 1];` (list **every** variable and memory range modified in the loop) |
<!-- endif -->
   | **Pre-state in `ensures`** | `ensures *out == *out + 1;` | `ensures *out == \old(*out) + 1;` |
   | **C calls & booleans in ACSL** | `requires !is_valid(p);` (C functions cannot be called in ACSL; `!` takes `boolean`, not `int`) | Inline the struct/pointer predicate directly (`p != \null && p->len <= MAX`), and write `x == 0` instead of `!x` |
   | **Arithmetic overflow in ACSL** | `requires a + b <= MAX;` (when intending 32-bit C wrap) | In ACSL, `+`, `-`, `*` on `integer` never overflow (`a + b` is mathematical integer sum; cast `(int)(a + b)` only if testing C truncation) |
<!-- if: division or pointer_params -->
   | **Partial terms (`/`, `%`, `*p`)** | `ensures x % y == 0;` or `ensures *p == 0;` (when `y == 0` or `p == \null` is possible) | Guard partial terms on the left of `==>` / `&&` (`y != 0 ==> x % y == 0`, `\valid_read(p) ==> *p == 0`); WP logic is 2-valued total, but E-ACSL uses 3-valued partial logic and aborts on undefined annotation terms |
<!-- endif -->
<!-- if: structs or unions -->
   | **Struct / union equality & `\with`** | `ensures *out == \old(*in);` or `{ s \with .x = 1 }` | Compare scalar fields individually (`ensures out->x == \old(in->x) && out->y == \old(in->y);`); whole-struct/union `==` and `\with` fail in E-ACSL, and cross-field union equality fails in WP `Typed` |
   | **Padded-struct / union `\initialized`** | `ensures \initialized(out_struct);` or `ensures \initialized(u);` | Assert field-level initialization (`ensures \initialized(&out_struct->field);`); E-ACSL checks all `sizeof(*p)` bytes in flat shadow memory and fails on uninitialized struct padding or smaller union members |
<!-- endif -->
<!-- if: strings -->
   | **C-string contracts & `\strlen`** | `requires valid_read_string(s);` (Frama-C libc axiomatic) or `\strlen(s) < n` | `requires valid_read_nstring(s, n);` or `requires valid_read_string(s);` (concrete bounded predicates from `fc_compat_types.h`) |
<!-- endif -->

<!-- if: strings -->
   - **Concrete Dual-Oracle C-String Predicates:** Frama-C libc standard library axiomatics (`\strlen`, uninterpreted `valid_read_string` relying on `\strlen(s) >= 0`) do not survive E-ACSL `-no-frama-c-stdlib` dynamic verification because host libc headers lack executable E-ACSL models for uninterpreted logic functions. The pipeline force-includes `fc_compat_types.h`, which provides concrete bounded predicates executable by both WP and E-ACSL:
     - `valid_read_nstring(char *s, integer n)`: validates reading up to `n` characters with null termination.
     - `valid_read_string(char *s)`: validates null termination within a bounded horizon (65536).
     - `valid_string(char *s)`: validates a writable null-terminated buffer.
     Always use `valid_read_nstring(s, max_len)` or `valid_read_string(s)` instead of `\strlen` or libc string axiomatics.
<!-- endif -->
<!-- if: arrays -->
   - **`\at(expr, Old)` distributes over array indexing:** `\at(a[i], Pre)` evaluates `a[\at(i, Pre)]` in the `Pre` state. Inside a loop where `k` is quantified, write `\at(a, Pre)[k]` or `loop invariant \forall integer k; 0 <= k < i ==> a[k] == \at(a[k], LoopEntry);`.
<!-- endif -->
<!-- if: recursion or loops -->
   - **Recursive `logic` functions must descend by `- 1`:** SMT solvers only trigger the inductive unfolding axiom when the recursive call uses `n - 1` (never `n / 2`).
<!-- endif -->
<!-- if: floats -->
   - **Floating-point comparisons:** always guard floating-point arguments with `requires !\is_NaN(x) && \is_finite(x);`.
<!-- endif -->
   - **Vacuous Contracts:** once all goals are proven, `run_wp_function.py` checks by itself whether your `requires` clauses contradict each other, and returns `unsound_proof` if they do. A defensive branch that your `requires` makes unreachable is not a failure, and neither is a deliberate `assert unreachable_branch: \false;`.
   - **What Gets Credited:** a Layer 4-6 unit needs at least one clause that says something about the function: `ensures L5_x: \true;` or `x == x` earns nothing. A called prototype with no contract at all fails the proof with `unsound_proof`, because Frama-C trusts a generated default contract for it. See `limits` in your WP report.
<!-- if: pointer_walk -->
   - **Pointer-Difference Equality Bridge & Pointer-Advancing Callee Postconditions (`p_end - p == 0 ==> p == p_end`):** Frama-C WP's `Typed` memory model does not export `b1 == b2 ==> (ofs1 - ofs2 == 0 ==> p1 == p2)` for two symbolic pointers even when `\base_addr(p) == \base_addr(p_end)` is asserted. Whenever a loop walks a pointer `p` toward `p_end = p0 + len` or branches on `p_end - p >= K`, anchor **both** `p` and `p_end` to the same base `\at(p, Pre)` via forward integer offsets:
     `loop invariant off_bound: 0 <= p - \at(p, Pre) <= p_end - \at(p, Pre);`
     `loop invariant ptr_anchor: p == \at(p, Pre) + (p - \at(p, Pre));`
     and place `/*@ assert end_anchor: p_end == \at(p, Pre) + (p_end - \at(p, Pre)); */` before the equality check so Qed reduces `p == p_end` to integer offset equality. Likewise, when `{function_name}` is a pointer-advancing parser helper (`const char *parse_x(const char *buf, const char *buf_end, ...)`), always export base-preservation and offset-progress postconditions:
     `ensures res_anchor: \result != \null ==> \base_addr(\result) == \base_addr(\old(buf)) && \result == \old(buf) + (\result - \old(buf));`
     `ensures res_bound: \result != \null ==> 0 <= \result - \old(buf) <= \old(buf_end) - \old(buf);` (use `< \result - \old(buf)` when the helper always consumes at least 1 byte such as a delimiter or EOL) so callers can preserve `loop invariant p == \at(p, Pre) + (p - \at(p, Pre));` and `loop variant buf_end - p;` across calls.
<!-- endif -->
<!-- if: assert_literal -->
   - **Unreachable `assert(!"string_literal")` Branches (Why3 `MemAddr.addr` vs `int`):** In Frama-C WP (`Typed` model), string literals in the `Cstring` table are typed as `int` IDs while `(char *)0` is `MemAddr.null`, causing `[Why3 Error] Type mismatch between frama_c_wp.memaddr.MemAddr.addr and int` on `assert(!"...")`. When `assert(!"...")` sits on an unreachable `default:` or state-machine branch, bound the switch/state variable in `requires` and `loop invariant`, and place `/*@ assert unreachable_branch: \false; */` immediately before `assert(!"...");` so Qed discharges the unreachable branch in 0ms without invoking Why3.
<!-- endif -->
<!-- if: macro_loops -->
   - **Unannotatable File-Scope `#define` Macro Loops:** If `{function_name}` invokes a file-scope `#define` macro that expands an embedded `while`/`for` loop, C preprocessor expansion prevents placing `/*@ loop invariant */` or `/*@ loop assigns */` inside the macro body without modifying C code. Still synthesize and prove `{function_name}`'s function contract (`requires`, `assigns`, `ensures`) and run the E-ACSL guardrail before reporting `stalled_after_k_retries` — the pipeline automatically merges sound, assigns-verified partial contracts so callers of `{function_name}` are not blocked.
<!-- endif -->

3. **Canonical C + ACSL Annotated Function Template:**
<!-- if: not loops -->
   ```c
   /*@ requires \valid(out_sum);
     @ terminates \true;
     @ exits \false;
     @ assigns *out_sum;
     @ ensures sum: *out_sum == a + b;
     @ ensures \result == 0;
     @*/
   int add_to(int a, int b, int *out_sum);
   ```
<!-- else -->
   ```c
   /*@ requires n >= 0;
     @ requires n > 0 ==> \valid_read(src + (0 .. n - 1));
     @ requires \valid(out_sum);
     @ requires \separated(out_sum, src + (0 .. n - 1));
     @ terminates \true;
     @ exits \false;
     @ assigns *out_sum;
     @ ensures \result == 0;
     @*/
   int sum_clamped(const int *src, int n, int *out_sum) {
       int acc = 0;
       /*@ loop invariant bound: 0 <= i <= n;
         @ loop invariant acc_range: 0 <= acc <= i * 100;
         @ loop assigns i, acc;
         @ loop variant n - i;
         @*/
       for (int i = 0; i < n; i++) {
           int v = src[i];
           if (v > 0 && v <= 100) {
               acc += v;
           }
       }
       *out_sum = acc;
       return 0;
   }
   ```
<!-- endif -->

---

## The Dual-Oracle Verification Loop (Run on Every Iteration)

Every time you edit `agents/{agent_id}/scratch/work/{c_file}` or `agents/{agent_id}/scratch/work/{header_file}`, run **both** oracles against your scratch work tree through the wrapper (`-TargetDir "{target_dir}" -RunDir "{run_dir}"`):

1. **Oracle 1 — Dynamic Anti-Hallucination Guardrail (`E-ACSL`):**
   ```text
   python3 /opt/framac-pipeline/scripts/run_eacsl_fuzz.py guardrail --sources {scratch_module_sources} workspace/harnesses/harness_{module_name}.c --functions {function_name} --out-bin agents/{agent_id}/scratch/guard_{function_name} --scratch-dir agents/{agent_id}/scratch/guard --corpus-dir workspace/corpus/{module_name} --extra-runs 100 --cppflags='{scratch_cppflags}' --ldflags='{ldflags}' --out-json agents/{agent_id}/scratch/guard_{function_name}.json
   ```
   - The shared corpus is replayed read-only; new units and artifacts stay in your scratch directory.
   - `--functions {function_name}` instruments only your function: its contract, loop annotations and RTE checks. That makes each iteration about an order of magnitude faster than instrumenting the whole module. The parent's re-check after the merge instruments the whole module.
   - The run uses a fixed seed and fixed limits, so the same inputs give the same verdict.
   - `rejected_overconstrained`: one of your annotations is FALSE on a real input. Read `runtime_trace` and `failure`, and fix it.
   - `code_fault`: an RTE assertion failed on a real input. This is a code defect, not a contract problem. Stop and return it (status `blocked`, include the guardrail report in `evidence`).

2. **Oracle 2 — Deductive Verification (`Frama-C WP + RTE`):**
   ```text
   python3 /opt/framac-pipeline/scripts/run_wp_function.py --file agents/{agent_id}/scratch/work/{c_file} --function {function_name} --out-dir agents/{agent_id}/scratch/wp --no-warn-unsigned-downcast --cppflags='{scratch_cppflags}' --out-json agents/{agent_id}/scratch/wp_{function_name}.json
   ```
   - `--no-warn-unsigned-downcast` stays in the command: C11 defines conversions to an unsigned type modulo 2^n (`(unsigned char)*buf`), and the parent's re-check uses the same flag. It is recorded in `reduced_checks`.
   - An `unsigned_overflow` goal on deliberate modular arithmetic (the range check `(unsigned char)c - 040u < 0137u`, or `while (n--)` on an unsigned counter) is well-defined C11 and false for some inputs. No annotation can prove it, and a `requires` excluding those inputs would break Rule 3. Declare only such lines, after reading their code: replace the flag with `--no-warn-unsigned --wrap-lines <line,line>` for this and every later run of this function, using the goals' current line numbers, and say so in `boundary_assumptions`. WP then proves the function with the unsigned checks off, so no proof can lean on a wrap, and runs again with them on. An `unsigned_overflow` goal not fully proved on a line you did not declare stays unproven (`unsigned_wraps.undeclared` in the output), including one only `Partially proven` because it follows a declared wrap. The parent's re-check follows your report, and the ledger records the lines.
   - `proven_under_hyp_count` goals rely on callee contracts; they are acceptable but are recorded as assumptions.
   - Concurrent provers (`-wp-par`) are sized automatically from your container's CPUs and memory.
   - Unchanged goals are answered from the run's proof cache, so re-running after a small edit only re-proves what changed.
   - `"status": "analysis_error"` means Frama-C was killed or timed out (`reason`: `oom_killed`, `timeout`, `crashed`). Nothing was proven or refuted. Re-run once; if it repeats, report `blocked` with the reason.

Run wrapper commands in the **foreground** and wait for completion: either run **Oracle 2 (`run_wp_function.py`) first** (catches ACSL syntax, `assigns`, and loop invariant errors in seconds) followed by **Oracle 1 (`run_eacsl_fuzz.py guardrail`)**, or run both in parallel inside a **single foreground wrapper call** (`<guardrail_cmd> & gpid=$!; <wp_cmd> & wpid=$!; wait $gpid $wpid`). Never leave detached background commands running across turns. A guardrail rejection still decides the iteration.

### Keep Your Best Candidate, Not Your Last

Both oracles record each iteration under `agents/{agent_id}/scratch/candidates/` and print a `candidate` block. On the same files, the first to finish says `next_action: "wait_for_other_oracle"`; the second says `evaluated: true` and carries the verdict.

- The best candidate passes the guardrail and has the fewest unproven goals, then the most proved goals. A candidate the guardrail rejects is never compared, however good its proof ratio: a stronger `requires` can raise that ratio by excluding inputs.
- `next_action: "continue"`: keep iterating.
- `next_action: "finished"`: this candidate is `all_proven` and passes the guardrail.
- `next_action: "restore_best_and_finish"` (the output also says `next_synthesis_focus: "no_progress_restore_best_and_finish"`): this iteration improved neither number. Stop iterating, and finish as below.
- Runs with `--prop` or `--dump-goal` are diagnostics and are not recorded.

Whenever you finish without `all_proven`, for any reason, first run `python3 /opt/framac-pipeline/scripts/prover_candidates.py restore-best --agent-id {agent_id}`. It puts the best candidate's files and reports back and regenerates the patch. Then take your status from the restored `agents/{agent_id}/scratch/wp_{function_name}.json`. After a `code_fault`, the report with the fault is at `agents/{agent_id}/scratch/candidates/last/guard_{function_name}.json` if a best candidate replaced it: name that file in `evidence`.

## Reference Manuals (Last Resort)

The Frama-C manuals are available as greppable Markdown under `{references_dir}`. Use them only when this brief and the tool output do not explain an ACSL parse or typing error, the meaning of a construct, or a WP option or message. Grep `{references_dir}/INDEX.md` for the topic and Read only the line range it reports (at most ~200 lines). Never read a manual whole. Start with the ACSL reference `acsl/frama-c-acsl-implementation.md`: contracts §2.3, loop annotations §2.4.2, `\at` §2.4.3, termination §2.5, logic definitions §2.6, memory built-ins §2.7. For WP itself, use `wp/frama-c-wp-manual.md`: supported annotations §2.1, options §2.4. The E-ACSL guardrail does not execute `assigns`, `loop assigns`, `decreases`, or lemmas (`acsl/e-acsl-implementation.md`, Figure 1.1), so only WP validates those clauses.

## Exit Criteria and Result

- Finish when `agents/{agent_id}/scratch/wp_{function_name}.json` reports `"status": "all_proven"` AND the guardrail reports `passed_dynamic_oracle`, or after `{max_retries}` full iterations with `unproven_goals_remain` (`stalled_after_k_retries`), or when a `candidate` block says `restore_best_and_finish` (`stalled_after_k_retries`), or immediately with `stalled_after_k_retries` when `next_synthesis_focus` is `"wp_dynamic_allocation_limitation_stop_now"` or `"budget_exhausted_write_result_json_now"`.
- Write your final annotation diff (against `agents/{agent_id}/scratch/base/`) to `agents/{agent_id}/scratch/{function_name}.patch` and reference it in `patch`. The parent splices your scratch overlay into `workspace/work/` via `workspace_overlay.py merge-agent` and re-verifies on the merged tree.
- Always write `agents/{agent_id}/scratch/result.json` using `python3 -c "import json, pathlib; pathlib.Path('agents/{agent_id}/scratch/result.json').write_text(json.dumps(res, indent=2))"` so ACSL backslashes (`\valid`, `\forall`, `\false`, `\at`) are properly JSON-escaped, and return **exactly one JSON object** and no surrounding prose:

```json
{
  "role": "prover",
  "agent_id": "{agent_id}",
  "file": "{c_file}",
  "function": "{function_name}",
  "status": "all_proven | stalled_after_k_retries | blocked",
  "patch": "agents/{agent_id}/scratch/{function_name}.patch or null",
  "evidence": [{"tool_output": "agents/{agent_id}/scratch/wp_{function_name}.json", "result": "all_proven"}],
  "unproven_goals": [],
  "strengthening_requests": [],
  "boundary_assumptions": [],
  "fault_hypothesis": null,
  "proof_gap": null
}
```

Set `fault_hypothesis` (`input_condition`, `predicate`, `why_not_reproduced`) only when you believe a specific input violates a specific goal (which creates a `needs_validation` bug candidate). When a goal stalls due to a WP/SMT limitation (for example `<stdlib.h>` dynamic allocation predicates `\freeable` / `allocates` or nonlinear arithmetic) or an unreachable branch rather than a code bug, leave `fault_hypothesis` as `null` and set `proof_gap` (`{"predicate": "...", "reason": "..."}`; must be `null` when `status` is `"all_proven"`). A stall without either is reported through `unproven_goals` alone.
