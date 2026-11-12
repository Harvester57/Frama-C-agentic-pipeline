# Phase 0: Build Capture, Frama-C Model & Threat Model

Issues encountered during build capture (`build_capture.py`), Phase 0 model parsing (`phase0_model.py`), architecture checks, and threat-model extraction (`trust.py`). For harness generation, reach gates, and seed recording, see [`./harnesses-and-seeds.md`](./harnesses-and-seeds.md). For Frama-C kernel header/libc issues, see [`./kernel-and-stubs.md`](./kernel-and-stubs.md).

---

### Symptom: `"status": "needs_build_recipe"` (Exit Code 3 From `build_capture.py run`)
- **Cause:** the target's build failed, built no C file, or has no recipe. Phase 0 has no inventory without a build, so it stops here. The checkpoint keeps the same status until a capture succeeds.
- **Fix:**
  1. Read `diagnostics` in `workspace/reports/build_capture.json`: `first_error` with its context, `missing_headers`, `candidate_packages` (a heuristic from headers, pkg-config modules, CMake packages and commands) and `packages_not_installed`.
  2. Ask the user for a corrected command, packages or flags. Never record a recipe the user has not given or confirmed.
  3. Record it with `run_metadata.py set-build ... --package <pkg>` and rerun the capture with `-BuildImage -Scratch -TargetPackages "<pkgs>"` (`--build-image --scratch --target-packages`). A success clears the status.
- **Without a recipe at all:** `build_capture.py propose` prints one guessed from the build files, as a starting point for the user.

### Symptom: `needs_build_recipe` With `the build compiled no C file` on a Recipe That Ends in `clean all` (PTF `make -C src/LibPtfCom clean all`)
- **Seen on:** ptf-original run-1, module scope `src/LibPtfCom`, 2026-11-10. `build.returncode` 0, `executions` recorded, but `compiles: []` and the log shows only `ar rcs libPtfCom.a *.o`.
- **Cause:** the capture runs the recipe with `MAKEFLAGS=-j15`. With a multi-goal invocation (`make clean all`), GNU make runs the goals **in parallel**: `all` sees the prebuilt `.o` files the target ships before `clean` removes them, so nothing recompiles (and `clean` then deletes the `.o` files afterwards). Not a pipeline defect: the recipe shape and the target's prebuilt tree trigger it.
- **Fix:** split the goals into sequential commands in the recipe: `make -C src/LibPtfCom clean && make -C src/LibPtfCom all`. The same applies to any target Makefile whose `clean` and `all` are given as one multi-goal invocation under the capture's parallel `MAKEFLAGS`.

### Symptom: `"status": "unsupported_architecture"` (Exit Code 5 From `build_capture.py run`)
- **Cause:** x86_64 Linux is the only supported platform. Frama-C's machdep (`gcc_x86_64`), the harness layouts (8-byte pointers) and the E-ACSL and sanitizer builds assume it. This is a limit of the pipeline, not a defect of the target. The capture's architecture guard stops Phase 0 in two cases, and the checkpoint keeps the status until a capture passes:
  - **The host is not x86_64.** `architecture.host` in `workspace/reports/build_capture.json` is `aarch64` or another machine. The guard stops before the target is copied or built.
  - **The build produced other code than x86_64.** `architecture.unsupported` lists each object, executable or shared library that is not ELF64, little-endian, x86-64, with its sources, what the file is (`ELF32 i386`, `ELF32 x86-64 (x32 ABI)`, `ELF64 aarch64`) and what in its command line made it so. The file's header decides. The command line (`-m32`, `-mx32`, `-m16`, `--target=`, a cross compiler's name) decides only for a file that cannot be read (`decided_by: command_line`). The guard stops after the build and before units, flags or entry points are derived.
- **Fix:** `diagnostics.instructions` in the report gives the same steps.
  1. **arm64 host (Apple Silicon, Graviton):** run the pipeline on an x86_64 machine. The images can be built and run as `linux/amd64` under emulation (`DOCKER_DEFAULT_PLATFORM=linux/amd64`), but this is not tested and not supported: it is slow, and the sanitizer and LibFuzzer builds of Phase 1 may misbehave.
  2. **`-m32`, `-mx32` or `-m16` in the flags:** ask the user for a recipe without it (`CFLAGS`, a configure or CMake option), record it with `run_metadata.py set-build`, and rerun the capture. The run then covers the x86_64 build only. Behaviour that exists only with 32-bit `long`, `size_t` and pointers is not analysed: say so in the report.
  3. **Cross compiler (`CC=<triple>-gcc`, `./configure --host=`, `CMAKE_TOOLCHAIN_FILE`, `clang --target=`):** ask for a native recipe without it, so the build image's own compiler builds the target.
  4. **Only some outputs are foreign** (a 32-bit test, a BPF or WebAssembly object, firmware next to host tools): name the native make targets in the recipe, so the others are not built.
  5. **The target builds for another architecture only** (firmware, a Windows or macOS build): it is out of scope for now. No recipe makes it pass.
- **Not checked:** a file the build removed, or LLVM bitcode from an LTO build, has no readable header. When its command line names no other target, it counts under `architecture.unknown` with a warning and the capture continues. Other architectures are not planned yet.

### Symptom: The Build Capture Times Out (1800 s) on a Build That Works by Hand
- **Cause:** a parallel build under `bear` can sit idle until the capture's timeout. Since `47d7c89`, a parallel build that fails **or times out** is retried once with one job on a fresh copy (`build.attempts` in `build_capture.json`), unless the recipe sets `MAKEFLAGS` or `CMAKE_BUILD_PARALLEL_LEVEL` itself. Only a serial build that also times out ends as `needs_build_recipe`. The retry gets a full new timeout, so the worst case is twice `--timeout`.
- **Fix:** rerun the capture through the broker (no `-NoBroker`), which sizes the build's jobs from its lease, or raise `--timeout` for a build that is just slow. If the recipe pins the parallelism through `MAKEFLAGS`, it gets no serial retry: drop it or set `-j1` yourself.

### Symptom: `needs_build_recipe` With `configure: error: cannot run /bin/bash ././config.sub` or `/bin/sh: 0: Illegal option -` (Windows Checkout)
- **Cause:** the target's working tree has CRLF line endings (`core.autocrlf=true`, or a `.gitattributes` `text` rule with the platform's native `eol`). `#!/bin/sh\r` or `#!/bin/sh -e\r` cannot run in the container, so `autogen.sh`, `config.sub`, `configure.ac`, `aclocal.m4` and every script fail. The git index is LF; only the checkout is wrong. Found on nettle (`file config.sub` says "with CRLF line terminators") and libseccomp (`autogen.sh` shebang triggers `/bin/sh: 0: Illegal option -`). This is a target-side checkout issue, not a pipeline defect.
- **Fix:** check the target out as LF, then start a **new run**: `git config --local core.autocrlf false`, `git config --local core.eol lf` (the `eol` setting is needed when `.gitattributes` marks files `text`), then `git rm -rq --cached . && git reset -q --hard` on a clean tree. The overlay of the earlier run holds the CRLF files and `workspace_overlay.py init` refuses a changed target, so do not resume it. Alternatively put a `sed -i 's/\r$//'` over the text files at the start of the recipe's command: the build runs in a copy, so the target stays untouched.
- **Check first:** `file config.sub configure.ac` (or `git ls-files --eol`) before the first capture on a Windows host.

### Symptom: A Generated Header (`config.h`) Is Missing in Eva, WP or the E-ACSL Build
- **Cause:** generated headers stay in the build tree on the scratch volume, and the later analyses read `workspace/work`, which holds only the target's source tree.
- **Fix:** **fixed** (`47d7c89`). The capture exports the headers the build generated to `workspace/snapshot/generated/` (`generated` in `build_capture.json`, `generated_dirs` in the snapshot manifest), and `target_env.with_include_flags` adds `-idirafter` for them to every Frama-C parse, the E-ACSL build, the harness probe and the sanitizer builds. If one is still missing, check that the run's capture predates `47d7c89` (rerun it) or that the header is listed under `generated`. Only as a stop-gap, copy it into `workspace/harnesses/include/`.

### Symptom: A File Compiled by Several Units With Different Flags Is Analysed in One Configuration Only
- **Cause:** a source file belongs to the first unit that compiles it, with that unit's flags (qlz's four executables build `quicklz.c` with different settings).
- **Fix:** none automatic yet. To analyse another configuration, write a harness whose flags state it.

### Symptom: A Unit's `parse.status` Is `gcc_fallback` in `phase0_model.json`
- **Cause:** Frama-C could not parse the unit with its build flags. Its functions and edges come from GCC's `-fcallgraph-info` instead, without loops, complexity, signatures or indirect-call candidates. `parse.error` holds Frama-C's first error, and the ledger flags the unit's functions (`bookkeeping.callgraph_fallback`).
- **Fix:** read `parse.error` and the log under `workspace/reports/phase0_model/`. The usual causes are the ones in [`./kernel-and-stubs.md`](./kernel-and-stubs.md) (host headers, compiler extensions); fix the cause, then rerun `phase0_model.py run`. Eva and WP will fail on that unit the same way until it parses. Fuzzing still works.

### Symptom: The Core Library Is `gcc_fallback` Because of a Build Variant Only the Compiler Accepts (nettle `fat-x86_64.c`)
- **Cause:** nettle's default build includes the runtime-CPU-dispatch ("fat") layer, whose `DEFINE_FAT_FUNC` macro expands to `return f(...)` inside `void` functions. GCC accepts it, Frama-C stops with `fat-x86_64.c:270: Return statement with a value in function returning void`. `libnettle.a` and `libnettle.so` then take the GCC call graph, which has **no signatures**: `generate_harness.py --api` cannot call any of its functions (`signature '' not understood`, 0 of 55 cluster harnesses), Eva and WP are blocked, and fuzzing falls back to the sanitizers.
- **Fix:** change the recipe so the analysed build is the portable one, with the user's confirmation: `./configure --disable-fat --disable-assembler`. The fix drops the dispatch layer and the assembly routines, so those code paths are not analysed; say so in the report. Then start a new run (capture, model, DAG). Look for the same pattern (`ifunc`, CPU-dispatch layers, `--disable-asm`/`--disable-assembler` flags) whenever a library's unit is `gcc_fallback` with a `return`-in-`void` or inline-asm error.

### Symptom: PTF Target-Side Defects Under Modern GCC (Not Pipeline Defects)
- **Seen on:** ptf-original run-2 (2026-11-10), target `/root/ptf/ptf-original/src`:
  - `ExternalInterfaces/LibChannelHandler/ChannelPTF_EFT.c:1184` calls `EftConnection(G_EftLogArray[G_EftLogIndex])` although `EftConnection` is declared and defined with no parameters (line 274/657). GCC accepts it as a warning; Frama-C rejects it, so the whole `libChannelHandler.a` unit is `gcc_fallback` (no signatures, Eva/WP blocked, sanitizers fuzzing only). The target is read-only and a fix would violate the ACSL-only overlay invariant, so the unit stays on the fallback; its byte-drivable entry points get a hand-written dispatch harness, the rest reach-gate exemptions.
  - `MonitoringAndControl/MibHandlers/ActiveCmdTable.c:521` (implicit declaration of `sleep`) and `SteeringManager/FastAlgosNasManagement.c:1639` (`strsep` with an incompatible pointer argument) are hard errors under the build image's GCC, so those two subdirectories do not build and were excluded from the run's scope with the user's confirmation.
- **Fix:** none in the pipeline; report both to the target's maintainers.

### Symptom: The Model Fails With the Dump Module (`kernel_ast.py` Compile Error)
- **Cause:** the image's Frama-C changed in a way `scripts/phase0_dump.ml` does not compile against.
- **Fix:** run `python3 /opt/framac-pipeline/scripts/phase0_model.py selftest`. The image build runs it too, so a Frama-C upgrade that breaks the dump module fails the image build first.

### Symptom: Every Unit Records `no_threat_model` (or `invalid_threat_model`)
- **Cause:** the target has no `THREAT_MODEL.md` with a fenced `framac-threat-model` JSON block (or the block does not validate against `schemas/threat_model.schema.json`).
- **Fix:** `python3 /opt/framac-pipeline/scripts/trust.py check-threat-model [PATH]` lists the errors (exit 2) or reports the missing block (exit 1). Put a corrected copy at `workspace/THREAT_MODEL.md` (it wins over the target's own), then run `trust.py run`, rebuild the DAG and rerun `security_props.py run`. Without a threat model, trust follows the default rules and only Layer 3 properties are generated.

### Symptom: `no_threat_model` Although `THREAT_MODEL.md` Has a `framac-threat-model` Block
- **Seen:** 2026-11-11, regex audit (no target run). `trust.extract_block` returned `(None, [])` for a block whose fence is indented by two spaces.
- **Cause:** `_FENCE_RE` in [`../../scripts/trust.py`](../../scripts/trust.py) wanted the fence at column 0, a closing fence identical to the opening, and the info word bare. An indented fence, a longer closing fence or `{framac-threat-model}` gave "no block", the same status as an absent file, so trust fell back to the default rules.
- **Fix (fixed 2026-11-11, uncommitted, [`../../scripts/trust.py`](../../scripts/trust.py)):** the regex scanner was replaced with linear CommonMark line scanner `_scan_code_fences` in `extract_block`, eliminating quadratic backtracking on unclosed fences. The fence may be indented by up to three spaces, the closing fence may be longer, and the info word may be in braces. A fence that names the block but cannot be read (inside a list item or a quote) is now `invalid_threat_model` with an error. Tests: [`../../tests/test_regex_hardening_infra.py`](../../tests/test_regex_hardening_infra.py).

### Symptom: A THREAT_MODEL.md With CRLF Line Endings Is Reported as `no_threat_model` ("has no structured block")
- **Seen on:** `test_threat_model_schema_takes_a_sink_format` on Windows (2026-11-10, while adding M5): `Path.write_text` wrote CRLF, and `trust.load_threat_model` found no block.
- **Cause:** `_FENCE_RE` in [`../../scripts/trust.py`](../../scripts/trust.py) accepted only spaces and tabs between the closing fence and the end of the line, so the `\r` of a CRLF file left the fence unclosed. A target checked out on Windows (or a threat model edited there) silently lost its threat model: only L3 was generated.
- **Fixed (worktree commit of M5):** the closing fence accepts a trailing `\r` (`[ \t\r]*$`); the test now reads the same block with LF and with CRLF line endings. A one-line hunk in `trust.py`, which the libc track also edits (its syscall readers), in another function.

### Symptom: A Product Unit With `check` in Its Name Is Marked `test` and Left Out of the Analysis (`test_reason: "name"` or `"test_sources"`)
- **Seen:** 2026-11-11, regex audit (no target run). `build_capture.test_reason("plugins/check_http", ...)` returned `"name"`; `libbounds.a` built from `bounds_check.c` and `sanity_check.c` returned `"test_sources"`.
- **Cause:** `TEST_WORDS` in [`../../scripts/build_capture.py`](../../scripts/build_capture.py) held `check` and `checks`, and any `_`, `.` or `-` separated word of a unit or file name was compared with it. Test units are dropped by `build_callgraph_dag.py`, `phase0_model.py` and `trust.py`, with only `test_reason` in the report.
- **Fix (fixed 2026-11-11, uncommitted, [`../../scripts/build_capture.py`](../../scripts/build_capture.py)):** `check` and `checks` are no longer test words in a name; a `check/` directory (`TEST_DIRS`) still marks a test. **Behaviour change:** a libcheck test built from `check_<x>.c` outside a test directory is now analysed as product code (`tests/test_build_capture.py::test_test_units_are_marked` changed accordingly). Tests: [`../../tests/test_regex_hardening.py`](../../tests/test_regex_hardening.py).

### Symptom: Unrecognized Compiler Variants Dropped Silently During Build Capture
- **Seen:** 2026-11-11, regex audit (Milestone M2). Intercepted build commands using `tcc`, `icx`, `afl-clang-fast`, or posix-suffixed compilers like `gcc-13-posix` were not recognized as compilers, and skipped compiler-like executions were dropped without warnings.
- **Cause:** `_COMPILER_RE` and `_TRIPLE_COMPILER_RE` in [`../../scripts/build_capture.py`](../../scripts/build_capture.py) lacked pattern alternatives for `tcc`, `icx`, `-fast`, and `-posix`. Skipped executions were dropped without recording.
- **Fix (fixed 2026-11-11, uncommitted, [`../../scripts/build_capture.py`](../../scripts/build_capture.py)):** expanded compiler regexes to recognize `tcc`, `icx`, `clang(?:-fast)?`, and `(?:-posix)?`. In `classify_executions`, tracked skipped compiler-like commands in `skipped_compiler_like` and surfaced them in `report["warnings"]`. Tests: [`../../tests/test_regex_hardening_infra.py`](../../tests/test_regex_hardening_infra.py).

### Symptom: Function Calls in Inline Bodies or Comments Falsely Identified as Declarations
- **Seen:** 2026-11-11, regex audit (Milestone M2). `build_capture.declared_names` matched function call sites inside inline function bodies, comments, and string literals.
- **Cause:** `declared_names` in [`../../scripts/build_capture.py`](../../scripts/build_capture.py) used regex search `rf"\b{re.escape(n)}\s*\("` over raw or preprocessed header text.
- **Fix (fixed 2026-11-11, uncommitted, [`../../scripts/build_capture.py`](../../scripts/build_capture.py), [`../../scripts/phase0_model.py`](../../scripts/phase0_model.py)):** updated `declared_names` to use C tokenization (`tokenize_c_acsl`), checking zero brace and parenthesis depth to ignore function bodies, comments, and strings. Added `phase0_model.header_declared_functions` to query model declarations directly from Phase 0 AST facts. Tests: [`../../tests/test_regex_hardening_infra.py`](../../tests/test_regex_hardening_infra.py).
