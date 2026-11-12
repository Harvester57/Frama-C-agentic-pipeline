# Resources, Caches, Make & Host Tooling

Issues encountered in container resource sizing (`resources.py`), content-addressed build/proof caches (`cache.py`), loop seed generation (`loop_seeds.py`), Make orchestration (`pipeline_make.py`, `templates/pipeline.mk`), benchmark path scrubbing (`benchmark.py`), reference extraction (`extract_references.py`), wrapper invocations (`wrappers/framac-docker.*`), and Windows/host test infrastructure.

The full resource and cache design guide is [`../guides/resources-and-caching.md`](../guides/resources-and-caching.md) (Section 9 lists symptoms). See [`./README.md`](./README.md) for the master troubleshooting index.

---

## Quick Resource, Cache & Lock Checklist

- **A command prints "queue position N" and waits:** the measured pool is busy. `python3 scripts/resources.py status` (on the host) lists the leases. Leases of killed wrappers are released once their containers exit (`resources.py gc`).
- **A WP report has `"status": "analysis_error"`:** Frama-C was killed or timed out (`reason`: `oom_killed`, `timeout`, `crashed`). Nothing was proven or refuted. The recorded peak memory makes the next lease larger, and the scheduler retries once before marking the units `blocked`.
- **Suspected stale cache result:** re-run with `FRAMAC_CACHE=off` and compare, then `python3 /opt/framac-pipeline/scripts/cache.py clear`.
- **The shared cross-run store stays empty:** only the exact allowlisted commands (`python3 /opt/framac-pipeline/scripts/pipeline_make.py run build|eva|wp-sweep|ingest`, with or without `$S/...`) may write it. Unrecognized commands, extra un-allowlisted options, or `FRAMAC_CACHE_RW=off` keep the store read-only (`FRAMAC_CACHE_MODE=ro` inside the container).
- **An ad-hoc command is OOM-killed at 1 GiB:** commands the broker does not recognise run as `light` (1 CPU, 1 GiB). Pass `-Class` / `--class` (for example `build` or `phase-dynamic`).
- **`RunLockTimeout`:** another container held the run's `ledger` or `merge` lock for longer than `FRAMAC_LOCK_TIMEOUT`. A holder whose heartbeat stopped (`FRAMAC_LOCK_STALE`, default 120 s) is broken automatically, and an interrupted merge is rolled back from `state/merge-journal.json` by the next merge.
- **Need the previous static behavior:** `FRAMAC_BROKER=off` (`-NoBroker`) for container sizing, `FRAMAC_SCHEDULER=waves` for Phase 3 dispatch.

---

## Resource Broker, Cache Keys & Make Orchestration

### Symptom: Static Command Classification Fails Open on Unknown Make Targets
- **Seen:** 2026-11-11, regex audit (Milestone M2). `resources.is_known_static_command` returned `True` for arbitrary target arguments such as `pipeline_make.py run unknown_target` or commands without the pipeline directory prefix.
- **Cause:** `is_known_static_command` in [`../../scripts/resources.py`](../../scripts/resources.py) used a denylist against `_DYNAMIC_MAKE_TARGETS` and optional prefix matching `(?:/opt/framac-pipeline/scripts/)?`, allowing untrusted or unrecognized target commands to pass as static analysis.
- **Fix (fixed 2026-11-11, uncommitted, [`../../scripts/resources.py`](../../scripts/resources.py)):** required strict `^/opt/framac-pipeline/scripts/` prefix for pipeline scripts, added `build-check` subcommand, and switched Make target validation to fail-closed allowlist `all(_is_static_make_target(t) for t in targets)` checking against `STAGE_OF_TARGET` and `_STATIC_MAKE_PREFIXES`. Tests: [`../../tests/test_regex_hardening_infra.py`](../../tests/test_regex_hardening_infra.py).

### Symptom: `loop_seeds.py` Under the Wrapper Reports `status: partial` With `analysis_error: insufficient_memory`
- **Fixed pipeline bug** (branch `papers-generalization`, uncommitted, 2026-11-10). Found by reading `_CLASS_PATTERNS` while building the tool; never reproduced under the wrapper (the container runs used plain `docker run`). Only reachable with `FRAMAC_LOOP_SEEDS=on`.
- **Cause:** `resources.infer_class` had no pattern for `loop_seeds.py`, so the command got the `light` class (1 CPU, 1024 MB), below what its WP rounds need.
- **Fix:** [`../../scripts/resources.py`](../../scripts/resources.py) maps `loop_seeds.py` to the `guardrail` class. Test: `tests/test_resources.py::test_infer_class_run_eacsl_fuzz_subcommand_precedes_build_module_name`.

### Symptom: Pasting Proven Loop Seeds Makes a Previously Proved Goal Time Out (Nested Loop)
- **Fixed pipeline bug** (branch `papers-generalization`, uncommitted, 2026-11-10). Seen on a toy benchmark of `scripts/loop_seeds.py` in `framac-analysis:latest`, no target run. Only reachable with `FRAMAC_LOOP_SEEDS=on` (default off).
- **Seen on:** function `fill` (two nested loops writing `m[r * cols + c]`): 12 of 13 goals proved before seeding, 15 of 17 after, and `\valid(m + (size_t)((size_t)(r * cols) + c))` went from proved to unproven at a 10 s goal timeout.
- **Cause:** the seeds are proven, so the goal is not false: the solver misses a nonlinear goal once more hypotheses are in context. Measured by running WP on `fill` with seed subsets: no seed 12/13; `c <= cols` alone on the inner loop loses the goal; `r <= rows` alone on the outer loop loses it and an assigns goal; `r < rows` alone on the inner loop keeps everything and is fast. The tool only checked that each seed proves, never what pasting them does to the function's other goals. (The first report of a duplicate `r <= rows` was wrong: it was the outer loop's seed and its restatement in the inner loop, redundant next to the inner `r < rows`.)
- **Fix:** [`../../scripts/loop_seeds.py`](../../scripts/loop_seeds.py) `no_harm`: after Houdini, one full WP run of the function without seeds and one with the proven seeds; if a goal is lost, it leaves out one seed of the loop the goal sits in (at most `MAX_NO_HARM_RUNS` seeded runs) and otherwise withholds every seed, printed as "Proven, but withheld". A check that cannot run withholds nothing and the report says the seeds were not checked. The restated outer bound is no longer generated when the strict outer guard is. On the rerun `fill` is back to 12/13 with all three seeds withheld; the other ten functions are unchanged.
- **Cost, and a limit:** the check adds two full WP runs per function with seeds: on the eleven toy functions the tool's total went from 45 s to 483 s. Leave-one-out did not find the one helpful subset for `fill` (`r < rows` alone), so the fallback loses that hint.

### Symptom: A Cached Result Is Restored After a `global invariant` or `volatile` Annotation Changed
- **Seen:** 2026-11-11, regex audit (no target run).
- **Cause:** `_GLOBAL_ACSL_DECL_RE` in `scripts/cache.py` decides which annotations next to another function stay in a function's digest. It did not list `global invariant` or `volatile`, so they were dropped from the digest and editing them did not change the key.
- **Fix (fixed 2026-11-11, uncommitted, `scripts/cache.py`):** both are in the pattern, so a function next to such an annotation gets a new key and its older entries are no longer hit. Tests: `tests/test_regex_hardening.py`.

### Symptom: Editing One Stub Header Re-runs Every Cached Eva Run and E-ACSL Build of the Run
- **Seen on:** K2 of [`../plans/templates-and-stubs-improvement-plan.md`](../plans/templates-and-stubs-improvement-plan.md), from reading `scripts/cache.py` (2026-11-10); not measured on a run.
- **Cause:** every cache key hashed all of `scripts/` and `templates/` (`cache.scripts_digest`), and after S2 the whole stub overlay (`workspace/stubs`) too. A contract added to one stub header therefore invalidated the results of modules that never include it.
- **Fix (fixed):** `cache.make_key` keys stub headers per module. A key whose material has a dependency manifest (`deps`: Eva, facts and E-ACSL/sanitizer builds, through `cache.memoize`) leaves `templates/fc_stubs/` and the overlay out of its global digests: the manifest (`gcc -M`/`clang -M` over the effective flags, which put the overlay and `templates/fc_stubs` on the include path) already names, and hashes, the stub headers that module's preprocessing read. Keys without a manifest (`slice-index`, `proofs`, `guardrail`) keep the digest of all of `templates/` and of the whole overlay. Everything else under `templates/` (the harness template, the E-ACSL runtime, `pipeline.mk`) still invalidates every key.
- **Limit:** the manifest is the include set `gcc -M` sees with Frama-C's defines; a stub header Frama-C reaches but `gcc -M` does not (none known) would not enter the key. If you suspect a stale result, compare with `FRAMAC_CACHE=off`.

### Symptom: `make help` Does Not List a Target `pipeline_make.py run` Accepts, or `facts-<mod>` and `module-<mod>` Compute Facts Differently
- **Seen on:** K3 of [`../plans/templates-and-stubs-improvement-plan.md`](../plans/templates-and-stubs-improvement-plan.md), from reading `templates/pipeline.mk`; no run failed on it.
- **Cause:** `help` omitted `eva-tune-base` (staged by `pipeline_make.STAGE_OF_TARGET`, in `.PHONY`), and `module-%` repeated the `facts-%` recipe line for line, so an option added to one would silently miss the other.
- **Fix (fixed):** `templates/pipeline.mk` has one `define FACTS_RECIPE` that both rules call (`$(call FACTS_RECIPE,$*)`; its body is tab-indented like any recipe, so `test_pipeline_makefile_builds_only_through_the_pipeline_scripts` still reads it, and GNU make keeps the `-` prefix after expansion, checked in `framac-analysis:latest`), and `help` lists `eva-tune-base`; `stubs` and `stub-check` are in `.PHONY`, `help` and the stage order (S2, S3). `tests/test_pipeline_make.py::test_pipeline_mk_lists_every_staged_target_and_shares_the_facts_recipe` checks that every target in `STAGE_OF_TARGET` is in `help`, in `.PHONY` and has a rule.

---

## Wrappers, Host Environment & Shared Infrastructure

### Symptom: Wrapper Exits With Code 2: `-NoInnerSandbox` / `--no-inner-sandbox` (or `-AllowDegradedSandbox` / `--allow-degraded-sandbox`) "is no longer supported"
- **Cause:** The bubblewrap layer was removed. The hardened container, with Docker's default seccomp and AppArmor profiles, is the only isolation boundary, and target-controlled binaries run under [`../../scripts/sandbox_exec.py`](../../scripts/sandbox_exec.py) (rlimits, env allowlist, timeout). The legacy flags fail hard rather than being silently ignored.
- **Fix:** Remove the flag from the command line or script. No replacement flag is needed.

### Symptom: PowerShell Splits Frama-C or Docker CLI Flags Containing `.` or `=`
- **Cause:** Windows PowerShell parses unquoted arguments containing `.` or `=` (like `-wp-model=Typed+ref` or `-report-csv=out.csv`) into multiple tokens.
- **Fix:** Always invoke container commands through [`../../wrappers/framac-docker.ps1`](../../wrappers/framac-docker.ps1) and double-quote any CLI flag containing `=` or `.`.

### Symptom: Benchmark Host Path Assertion Bypassed by Dictionary Keys, UNC Paths, or Flagging Relative Paths
- **Seen:** 2026-11-11, regex audit (Milestone M2 Iteration 2). `benchmark.assert_no_host_paths` did not inspect dictionary keys, ignored Windows UNC (`\\server\share\...`, `\\wsl$\...`), forward-slash UNC (`//server/share`), and driverless root paths (`\Users\...`), while falsely raising `BenchmarkError` on relative paths starting with `./` or `../`.
- **Cause:** `_HOST_PATH_RE` in [`../../scripts/benchmark.py`](../../scripts/benchmark.py) used negative lookbehind `(?<![\w/:])` which excluded `.`, lacked UNC/network patterns, and `assert_no_host_paths` only traversed dictionary values, skipping keys.
- **Fix (fixed 2026-11-11, uncommitted, [`../../scripts/benchmark.py`](../../scripts/benchmark.py)):** updated `_HOST_PATH_RE` with lookbehind `(?<![.\w/:])`, added explicit container traversal detection `/framac-run/\.\.`, added UNC and driverless backslash branches, added dictionary key validation `assert_no_host_paths(key, f"{where}.(key)")`, and updated `scrub_host_paths` to scrub dictionary keys. Tests: [`../../tests/test_regex_hardening_infra.py`](../../tests/test_regex_hardening_infra.py).

### Symptom: Technical Terms and Single-Letter Identifiers at Page Bottom Falsely Dropped as Page Numbers
- **Seen:** 2026-11-11, regex audit (Milestone M5). In `scripts/extract_references.py`, words such as `mix`, `dim`, `c`, `C`, `MIX`, `I`, `X`, `d`, `cc` or malformed repetitions `lxxxx`, `iiii`, `vv` occurring on the last line of a page were stripped as page numbers.
- **Cause:** `_PAGE_NUMBER_RE` used `^\s*(?:\d+|[ivxlcdm]+)\s*$` with `re.IGNORECASE`. The unbounded character class `[ivxlcdm]+` with case insensitivity matched any English word composed of those letters or single capital letters/acronyms.
- **Fix (fixed 2026-11-11, uncommitted, [`../../scripts/extract_references.py`](../../scripts/extract_references.py)):** constrained Roman numeral matching to valid lowercase Roman numeral sequences from 1 to 89: `^\s*(?:\d+|(?=[ivxl])(?:xc|xl|l?x{0,3})(?:ix|iv|v?i{0,3}))\s*$`, removing `re.IGNORECASE`. Valid lowercase page numerals (`iv`, `xii`, `xxxix`, `xliv`, `lxxxviii`) match and are dropped, while ordinary words and uppercase identifiers are preserved. Tests: [`../../tests/test_regex_hardening_stubs.py`](../../tests/test_regex_hardening_stubs.py).

### Symptom: Circular Import Hazards or Divergent Implementations of Memory and Dependency Parsers
- **Seen:** 2026-11-11, regex audit (Milestone M5). Modules across different layers (`cache.py`, `resources.py`, `build_capture.py`, `ledger.py`) had duplicate definitions of Makefile dependency parsers (`parse_make_deps`), memory size parsers (`parse_mem`, `_parse_size`), fuzzer definitions (`_FUZZER_INIT_DEF_RE`, `_FUZZER_ENTRY_DEF_RE`), and kernel rename regexes (`KERNEL_RENAME_RE`).
- **Cause:** lack of a common foundational patterns module led each script to define its own regexes and parser helpers, risking subtle divergences (e.g. `cache._parse_size` returning bytes vs `resources.parse_mem` returning MiB). Importing helpers between scripts would create circular dependency cycles between low-level infrastructure modules.
- **Fix (fixed 2026-11-11, uncommitted, [`../../scripts/patterns.py`](../../scripts/patterns.py)):** created `scripts/patterns.py` as a pure standard-library module with zero internal pipeline imports. Exported canonical compiled regexes (`C_IDENT_RE`, `SLUG_RE`, `LOCATION_RE`, `MODULE_RE`, `CALL_SITE_RE`, `KERNEL_RENAME_RE`, `FUZZER_INIT_DEF_RE`, `FUZZER_ENTRY_DEF_RE`, `DOMAIN_RE`, `ASSIGNS_RE`, `TREE_TAIL_RE`, `WORK_PREFIX_RE`) and unified parsers `parse_mem(..., as_bytes=...)` and `parse_make_deps(text, cwd=...)`. Downstream scripts imported these canonical implementations. Tests: [`../../tests/test_cache.py`](../../tests/test_cache.py), [`../../tests/test_resources_api.py`](../../tests/test_resources_api.py), [`../../tests/test_build_capture.py`](../../tests/test_build_capture.py).

---

## Test Suite & Windows Checkout Issues

### Symptom: `AssertionError: ... is a stale copy of skills/...: SKILL.md differ` on Windows Checkouts
- **Seen:** 2026-11-11, regex audit (Milestone M5). Tests `test_framac_skills_mirror_is_in_sync` and `test_brief_templates_synced_and_render_cleanly` failed on Windows checkouts where symlinks are plain directories.
- **Cause:** in git tracking, `.agents/skills/` and `.claude/skills/` are symlinks (`120000`). On Windows checkouts without native symlink support, git creates physical directories. When files under `skills/` are updated or new brief templates added (`skills/framac-slice/stub_author_brief.md`), the physical copies become stale.
- **Fix (fixed 2026-11-11, uncommitted):** synchronized all skill files from `skills/` to `.agents/skills/` and `.claude/skills/` via binary copy (`write_bytes`), maintaining byte-exact equivalence and LF line endings without CRLF translation. Tests: [`../../tests/test_extract_references.py`](../../tests/test_extract_references.py), [`../../tests/test_diagnostic_hints.py`](../../tests/test_diagnostic_hints.py).

### Symptom: `test_budget_is_capped_by_env_and_free_disk` Fails Under `-n` With `assert ... == int((0.25 * <free>))`
- **Fixed test race, not a pipeline defect** (seen 2026-11-09 in a full `-n 6` run on branch `formal-discovery-tiers` while an analysis was running; passes alone).
- **Cause:** the test read `shutil.disk_usage(tmp_path).free` once and `Store.budget_bytes()` read it again; other writers (parallel workers, a live run) changed the free space in between.
- **Fix:** [`../../tests/test_cache.py`](../../tests/test_cache.py) pins `cache.shutil.disk_usage` to one measurement.

### Symptom: `test_sh_new_run_allocation_is_atomic_under_concurrency` fails on Windows with `child_copy: cygheap read copy failed ... Win32 error 299` or return code `3221225794`
- **Seen:** 2026-11-09, full `python -m pytest tests -n auto` in the formal-discovery Tier 4 worktree while five other sessions ran their own suites on the same Windows host. Failed twice in the full suite; `tests/test_run_identity_wrappers.py` passes alone (`-n 0`).
- **Cause:** not a pipeline defect. The test starts many Git Bash (`bash.exe`) processes at once; under heavy host load Cygwin's `fork` fails (Win32 error 299, or `0xC0000142` STATUS_DLL_INIT_FAILED as the return code), so `mkdir` in `framac-docker.sh`'s run allocation never runs. The atomicity being tested is not involved.
- **Fix:** none needed in the pipeline. Re-run the file alone (`python -m pytest tests/test_run_identity_wrappers.py -n 0`) when the host is busy. **Open test gap:** the test could skip or retry on a Cygwin fork failure instead of reporting it as an allocation race (O12 in [`../plans/open-topics-remediation-plan.md`](../plans/open-topics-remediation-plan.md)).
