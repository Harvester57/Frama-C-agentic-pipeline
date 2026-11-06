# libssh2 Onboarding: Pipeline Blockers (Frama-C Agentic Verification Pipeline)

> [!WARNING]
> **These are defects in the pipeline's own scripts and toolchain, NOT defects in the
> libssh2 target.** No libssh2 bug has passed the Crash Verification Gate yet; the Phase 1/2
> build never completed. Do not add these to the Master Vulnerability Index or the Target
> Summary in [`../README.md`](../README.md).

- **Target:** [`libssh2/libssh2`](https://github.com/libssh2/libssh2) (onboarding run, `standard` profile)
- **Run directory:** `~/framac-pipeline/libssh2/run-1/`
- **Date:** 2026-11-06
- **Status:** Phase 0 complete (DAG 609 functions / 21 waves, ledger 938 units, checkpoint saved).
  Phase 1/2 build blocked by the items below. Each item stands alone with evidence, a
  reproducer, and a suggested fix.

## Environment

| Component | Version |
| :--- | :--- |
| Frama-C / `e-acsl-gcc` | 34.0~~dev (Selenium), Opam 5.5, `/home/opam/.opam/5.5/bin/` |
| Container | `framac-pipeline:latest`, target mounted read-only at `/target`, run dir at `/framac-run` |
| Target configuration | CMake `Debug`, `-DHAVE_CONFIG_H -DLIBSSH2_OPENSSL`, zlib enabled; generated `libssh2_config.h` copied to `workspace/harnesses/gen/` |
| Slices | 21 modules (26 compiled `src/*.c` + dual harness each); 9 excluded (Tier 3 glue, dead backend TUs, no harness) |

---

## PB-1 — `extract_functions_from_code` mis-parses function-pointer-returning definitions

- **File:** `scripts/build_callgraph_dag.py` (`extract_functions_from_code`), consumed by
  `scripts/run_eacsl_fuzz.py` (`_discover_slice_functions`, used at `:669` and `:815`).
- **Severity:** High — blocks E-ACSL instrumentation for every module whose discovery set
  includes `session.c` (13/21 modules in this run).
- **Observed:** a definition whose **return type is a function pointer**,

  ```c
  static void *(ssh2_default_alloc)(size_t count, void **abstract) { ... }
  ```

  is extracted as a function **named `void`** (the parenthesized declarator
  `*(ssh2_default_alloc)(...)` defeats the name capture; the return-type token wins).
- **Impact:** the bogus name is joined into `-rte-select` / `-e-acsl-functions`; Frama-C's RTE
  plugin rejects it at option parsing:

  ```
  [rte] User Error: incorrect argument for option -rte-select (no function 'void').
  [kernel] Plug-in rte aborted: invalid user input.
  ```

  The troubleshooting doc's safety net ("Names Frama-C still rejects are dropped once and
  listed in `rte_select_dropped`") does **not** fire: `void` is a syntactically valid
  identifier, so the drop logic (which handles kernel-level *unknown function* errors) never
  sees a rejection — RTE fails at option validation instead.
- **Reproducer** (inside the container, from the run dir):

  ```bash
  python3 - <<'EOF'
  import sys, json, subprocess
  sys.path.insert(0, '/opt/framac-pipeline/scripts')
  from eacsl_toolchain import preprocess_source
  from build_callgraph_dag import extract_functions_from_code
  from pathlib import Path
  cpp = json.load(open('workspace/harnesses/harness_misc.json'))['cppflags']
  raw = preprocess_source(Path('workspace/work/src/session.c'), cpp)
  names = [f['name'] for f in extract_functions_from_code(raw, path='workspace/work/src/session.c')]
  print('void' in names)   # True
  EOF
  ```

- **Suggested fix:** in `extract_functions_from_code`, treat a parenthesized declarator
  `*(name)(params)` as the function's identifier (skip the `*(` and take the inner
  identifier), or reject candidate names that are C type keywords (`void`, `char`, `int`,
  `unsigned`, `signed`, `long`, `short`, `float`, `double`, `struct`, `union`, `enum`,
  `const`, `volatile`) before they reach `-rte-select`. The second option is the smaller
  change and also hardens the `-rte-select` assembly in `run_eacsl_fuzz.py`.
- **Workaround used:** none (unblocks only by patching the extractor or passing explicit
  per-module `--functions` lists taken from the DAG, whose names are correct).

## PB-2 — Sidecar source paths assume a flat overlay for DAG-derived sources

- **Files:** `scripts/generate_harness.py` (sidecar `sources` assembly) and
  `scripts/pipeline_make.py` (`normalize_source`, `WORK_DIR = "workspace/work"`).
- **Severity:** High — every non-`include_source` module failed its primary build in this run.
- **Observed:** the DAG stores `required_sources` as **bare, module-dir-relative** names
  (`misc.c`). `generate_harness.py` merges them into the sidecar prefixed with
  `workspace/work/`, and `normalize_source` maps a bare name to `workspace/work/<name>` —
  both assuming the overlay root is flat. For a target whose sources live in a subdirectory
  (`src/`), the merged paths do not exist:

  ```
  [kernel] User Error: source file 'workspace/work/chacha.c' does not exist
  [kernel] Frama-C aborted: invalid user input.
  clang: error: no such file or directory: 'workspace/work/bcrypt_pbkdf.c'
  ```

  (The sanitizer-engine fallback then fails on the same missing files, so the module has no
  binary at all.)
- **Suggested fix:** store `required_sources` as target-relative paths (`src/misc.c`) in the
  DAG, or normalize bare names against the module's directory (the DAG records each module's
  file list, so the module dir is derivable). `normalize_source` already handles
  `workspace/`-prefixed and `/target/`-prefixed forms correctly; only the bare-name branch
  is wrong.
- **Workaround used:** sidecar sources rewritten post-generation to existing
  `workspace/work/src/*.c` paths (see `workspace/harnesses/gen_all.py` in the run dir).

## PB-3 — DAG `required_sources` closure misses real cross-file edges

- **File:** `scripts/build_callgraph_dag.py` (closure computation).
- **Severity:** Medium — undefined references at link time for `include_source` harnesses.
- **Observed:** the closure missed two real edges:
  - `session.c → global.c` (`ssh2_init_if_needed`, called at `session.c:426`);
  - `userauth.c → userauth_kbd_packet.c`
    (`userauth_keyboard_interactive_decode_info_request`, called at `userauth.c:1982`).

  ```
  /usr/bin/ld: .../harness_agent-*.o: in function `libssh2_session_init_ex':
  workspace/work/src/session.c:426: undefined reference to `ssh2_init_if_needed'
  /usr/bin/ld: ...: in function `libssh2_userauth_keyboard_interactive_ex':
  workspace/work/src/userauth.c:1982: undefined reference to
      `userauth_keyboard_interactive_decode_info_request'
  ```

  Both calls are direct, non-macro call sites in compiled code — the regex callgraph should
  see them.
- **Suggested fix:** after the regex pass, verify each `required_sources` closure by a
  compile/link probe (the pipeline already builds every slice; a link failure with undefined
  references could drive one repair iteration that re-runs discovery with a
  definition-site-driven fallback). Alternatively check why the edge extraction missed
  direct calls in `session.c`/`userauth.c` (both are plain `ssh2_init_if_needed();` /
  `userauth_keyboard_interactive_decode_info_request(session);` statements).
- **Workaround used:** full-library source lists (all 26 compiled `src/*.c` in every sidecar).

## PB-4 — Frama-C kernel crash: duplicate libc property registration under `-include`

- **Severity:** High — blocks E-ACSL for all 8 `include_source` modules (their sanitizer
  fallbacks build, so the modules still get ASan+UBSan fuzz binaries).
- **Observed:** after the opaque-handle fix (PB-5) is delivered via `-include`, Frama-C
  aborts during E-ACSL instrumentation of the whole-library single-TU harnesses:

  ```
  [kernel] Failure: trying to register twice property 'assumes nonnull_p: ptr ≢ \null'.
    That is forbidden (kernel invariant broken).
  [kernel:backtrace] Raised at Fclib__Log.Register.fatal.finally in file "src/lib/utils/log.ml", line 1157
  ```

  (`nonnull_p` is a libc `assumes` property; the location is kernel-generated.)
- **Hypothesis (unverified):** the force-included compat header
  (`-include workspace/harnesses/ossl_compat.h`, which `#include <openssl/evp.h>`) causes the
  same libc specification to be registered twice in the single-TU build. The 8 affected
  modules are exactly the `include_source` ones; the 13 non-include-source modules get past
  the kernel (they fail later, at PB-1's option parsing).
- **Suggested isolation step:** rebuild one `include_source` module (e.g. `session`) three
  ways — (a) without the compat header (expect PB-5's alignof errors back), (b) with the
  compat header delivered source-side (`#include "ossl_compat.h"` after the OpenSSL headers
  in the harness) instead of `-include`, (c) as-is. If (b) passes, the fix is to stop using
  `-include` for type-completion headers and let the harness include them after the system
  headers.
- **Workaround used:** none; the 8 modules run on the sanitizer fallback engine.

## PB-5 — E-ACSL emits `_Alignof` on pointed-to opaque external handles (known, documented)

- **Severity:** Medium — compile error of the instrumented source; fixed per the playbook.
- **Observed:** RTE generates `\aligned(ptr, alignof(EVP_PKEY))`-style assertions; E-ACSL
  compiles them to `_Alignof(EVP_PKEY)` on incomplete types:

  ```
  workspace/harnesses/fuzz_agent.instrumented.c:479689: error: invalid application of
  'alignof' to an incomplete type 'EVP_PKEY' (aka 'struct evp_pkey_st')
  ```

  Affected types in this run: `EVP_PKEY`, `EVP_MD_CTX`, `EVP_CIPHER_CTX`, `EVP_MAC_CTX`,
  `BIGNUM`, `BN_CTX` (OpenSSL 3.5.7 opaque handles).
- **Fix (applied, per [`../troubleshooting.md`](../../troubleshooting.md) §"call to undeclared
  function 'X' or invalid application of 'alignof'"):** complete each handle with a single
  dummy member — `workspace/harnesses/ossl_compat.h` in the run dir, force-included via
  `-include`. This resolved every alignof error; the residual kernel crash is PB-4.

---

## Harness-authoring notes (not pipeline defects)

Recorded so the fixing model does not re-trip them; both are already fixed in the run dir.

1. **`--header` must name the header that actually declares the entry function.** Passing the
   public `include/libssh2.h` for modules whose entry functions are declared in
   `src/libssh2_priv.h` or module headers made `generate_harness.py` synthesize an
   **incompatible** declaration (Frama-C: *"Incompatible declaration for ssh2_base64_decode"*)
   and left the sanitizer fallback without any declaration (*"call to undeclared function
   'ssh2_base64_decode'"*). Per-module headers: `libssh2_priv.h` (bcrypt_pbkdf, misc, packet,
   pem, transport, userauth_kbd_packet), `chacha.h`, `cipher-chachapoly.h`.
2. **Check arities against the definition, not the DAG.** `crypt_init_chacha20_poly` takes 9
   parameters (`encrypt`, `privkeyfile` after `free_secret`); a call-expr written from the
   DAG's truncated `params` string passed 7.

## Run-state summary at handoff

| Item | State |
| :--- | :--- |
| Ledger | 938 units: 763 planned, 166 out_of_scope (dead backend TUs, Tier 3 glue), 9 deferred (Tier 3) |
| Built (sanitizer engine) | agent, hostkey, kex, openssl, publickey, session, userauth, keepalive |
| Blocked (PB-1) | bcrypt_pbkdf, chacha, cipher-chachapoly, comp, crypt, mac, misc, packet, pem, scp, transport, userauth_kbd_packet |
| Blocked (PB-4) | the 8 built modules' E-ACSL engine (sanitizer binaries usable) |
| No harness (by design) | channel, sftp (socket/channel-bound state machines; WP route), global, version, poly1305 (Tier 3, deferred) |
| Out of scope | libgcrypt, mbedtls, wincng, os400qc3 (backend TUs empty under `-DLIBSSH2_OPENSSL`) |

Key artifacts in the run dir (`~/framac-pipeline/libssh2/run-1/`):
`workspace/harnesses/gen_all.py` (harness driver incl. per-module headers and call-exprs),
`workspace/harnesses/ossl_compat.h`, `workspace/harnesses/fz_hooks.h` (session send/recv
callback hooks), `workspace/harnesses/agent_ipc_stubs.h` (ssh-agent socket/connect/send/recv
interposition), `workspace/reports/callgraph_dag.json`, `coverage-ledger.json`.

---

## Resolution (pipeline fixes, verified against this run dir)

- **PB-1** — `_resolve_declarator` (`scripts/build_callgraph_dag.py`) now resolves all
  parenthesized declarator shapes (`ret (*fn)(params)`, `ret (*(fn)(params))`,
  `ret (*fn(params))(fp)`) and never accepts a type keyword as a name; macro-wrapped
  definitions (`LIBSSH2_ALLOC_FUNC(ssh2_default_alloc)`) are expanded via the macro table.
  `_discover_slice_functions` (`scripts/run_eacsl_fuzz.py`) additionally filters type
  keywords before `-rte-select`. Re-running discovery on `session.c` now yields
  `ssh2_default_alloc/free/realloc` and no `void`.
- **PB-2** — `build_callgraph_dag.py` maps compile_commands paths recorded against another
  root (e.g. `/target`) into the overlay by longest suffix match, so the DAG stores
  `src/...` keys; `normalize_source` (`scripts/pipeline_make.py`) and
  `_merge_dag_harness_sources` (`scripts/generate_harness.py`) resolve bare/stale names by
  overlay suffix glob. Rebuilding the DAG over `workspace/work` now yields 0 bare file keys.
- **PB-3** — `build_module_binary` (`scripts/run_eacsl_fuzz.py`) parses
  `undefined reference to 'X'` on link failure, maps X to its defining source via the DAG,
  appends it, and retries once (`link_repair` in the result JSON).
- **PB-4/PB-5** — target-compat headers are now delivered source-side:
  `generate_harness.py --compat-include <header>` emits `#include` in the harness after the
  module header (sidecar field `compat_includes`) instead of `-include` in cppflags, which
  re-registered libc properties per merged TU and crashed the kernel. See
  `docs/troubleshooting.md`. The exact `-include` trigger still warrants the 3-way isolation
  experiment in the container before re-running Phase 1/2.
- **Harness notes** — `generate_harness.py` auto-detects the header that actually declares
  the entry function when `--header` does not, and validates `--call-expr` arity against the
  definition parsed from the sources.

Regression tests: `tests/test_callgraph_dag.py` (declarator shapes, macro-wrapped defs,
foreign-path mapping), `tests/test_pipeline_make.py` (overlay `normalize_source`),
`tests/test_fuzz_link_repair.py` (undefined-reference repair, keyword filter),
`tests/test_harness_compat.py` (compat includes, declaring header, arity).
