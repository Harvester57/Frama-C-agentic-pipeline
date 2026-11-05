# Targets of the Make-driven pipeline phases.
#
# workspace/build/Makefile, written by `pipeline_make.py gen`, includes modules.mk (module lists
# and every per-module value: sources, flags, tuning, each already a quoted shell word) and then
# this file. Make runs from the run directory (/framac-run), the cwd every script assumes. Use
# `pipeline_make.py run <targets...>`: it regenerates modules.mk, sizes -j from resources.py and
# runs targets in pipeline order (for example ingest only after fuzz and eva).
#
# Every target is phony. Repeated runs stay cheap because builds and Eva results are cached by
# content and ingestion skips report digests it has already seen (state/ingested.json), not
# because of file timestamps, which are coarse on 9p and NFS.
#
# Every recipe that runs a pipeline script goes through the container broker (resources.py run),
# which admits it by CPU and memory. With --output, a recipe succeeds once the tool has written
# its report, even if the tool itself failed: the report carries the failure into the ledger.
# Flag-valued options use the --opt=value form, so a value starting with '-' is never read as an
# option.

S          ?= /opt/framac-pipeline/scripts
PY         ?= python3
TARGET_DIR ?= /target

RUN := $(PY) $(S)/resources.py run
PM  := $(PY) $(S)/pipeline_make.py
SELFTEST_JSON := workspace/reports/eacsl_selftest.json

BUILD_TARGETS  := $(addprefix build-,$(FUZZ_MODULES))
FUZZ_TARGETS   := $(addprefix fuzz-,$(FUZZ_MODULES))
COVERAGE_TARGETS := $(addprefix coverage-,$(FUZZ_MODULES))
EVA_TARGETS    := $(addprefix eva-,$(EVA_MODULES))
MODULE_TARGETS := $(addprefix module-,$(MODULES))

MAKEFLAGS += --no-builtin-rules
.SUFFIXES:
.DEFAULT_GOAL := help
.PHONY: help slice-init seed build selftest fuzz coverage eva ingest replay wp-queue wp-sweep report \
        $(BUILD_TARGETS) $(FUZZ_TARGETS) $(COVERAGE_TARGETS) $(EVA_TARGETS) $(MODULE_TARGETS)

help:
	@echo 'Targets: slice-init seed build selftest fuzz coverage eva ingest replay wp-queue wp-sweep report module-<mod>'
	@echo 'Fuzz modules: $(FUZZ_MODULES)'
	@echo 'Eva modules: $(EVA_MODULES)'

# --- Phase 0 ---------------------------------------------------------------------------------

# Shadow overlay of the read-only target, then the call-graph DAG of the work tree.
slice-init:
	$(RUN) --class light --key slice-init -- $(PY) $(S)/workspace_overlay.py init --target $(TARGET_DIR) --overlay workspace
	$(RUN) --class light --key slice-init -- $(PY) $(S)/build_callgraph_dag.py --target workspace/work \
		--out workspace/reports/callgraph_dag.json --emit-compile-commands workspace/reports/compile_commands.json

# Ledger seed (scope paths from run-metadata.json), validation, checkpoint of phase 0. The
# checkpoint is initialized only once, so seeding again never rewinds the recorded progress.
seed:
	$(RUN) --class light --key seed -- $(PY) $(S)/ledger.py seed --dag workspace/reports/callgraph_dag.json $(SEED_SCOPE_ARGS)
	$(RUN) --class light --key seed -- $(PY) $(S)/validate_artifacts.py run-dir .
	test -f state/progress.json || $(RUN) --class light --key seed -- $(PY) $(S)/checkpoint.py init state --target $(TARGET_DIR)
	$(RUN) --class light --key seed -- $(PY) $(S)/checkpoint.py save-phase state --phase 0 \
		--from-file workspace/reports/callgraph_dag.json

# --- Phases 1 and 2 --------------------------------------------------------------------------

# Compile only: E-ACSL, or the sanitizer build when the cached selftest failed. Static (it never
# runs target code), so it does not depend on the selftest.
build: $(BUILD_TARGETS)
$(BUILD_TARGETS): build-%:
	$(RUN) --class build --key $* --output workspace/build/$*.build.json -- \
		$(PY) $(S)/run_eacsl_fuzz.py build --module $* --sources $(SOURCES_$*) \
		--out-bin workspace/harnesses/fuzz_$* --cppflags=$(CPPFLAGS_$*) --ldflags=$(LDFLAGS_$*) \
		$(if $(FUZZ_NO_RTE_INIT_$*),--no-rte-initialized) \
		--selftest-json $(SELFTEST_JSON) --out-json workspace/build/$*.build.json

# The E-ACSL toolchain canary (runs a compiled canary, so dynamic).
selftest:
	$(RUN) --class selftest --key selftest --output $(SELFTEST_JSON) -- \
		$(PY) $(S)/run_eacsl_fuzz.py selftest --out-json $(SELFTEST_JSON)

# One campaign per module. Its effort is a CPU-second budget spread over the workers the lease
# allows; FUZZ_MAX_TIME_<mod> overrides the wall time.
fuzz: $(FUZZ_TARGETS)
$(FUZZ_TARGETS): fuzz-%: selftest build-%
	$(RUN) --class fuzz --key $* --output workspace/reports/fuzz/$*.json -- \
		$(PY) $(S)/run_eacsl_fuzz.py campaign --module $* --sources $(SOURCES_$*) \
		--out-bin workspace/harnesses/fuzz_$* --corpus-dir workspace/corpus/$* --artifacts-dir workspace/crashes/$* \
		--workers auto --fuzz-budget $(FUZZ_BUDGET_$*) \
		$(if $(FUZZ_MAX_TIME_$*),--max-time $(FUZZ_MAX_TIME_$*)) $(if $(FUZZ_DICT_$*),--dict=$(FUZZ_DICT_$*)) \
		$(if $(FUZZ_NO_RTE_INIT_$*),--no-rte-initialized) \
		--cppflags=$(CPPFLAGS_$*) --ldflags=$(LDFLAGS_$*) \
		--selftest-json $(SELFTEST_JSON) --out-json workspace/reports/fuzz/$*.json

# Which functions each module's corpus executes. It replays the corpus as it stands: a dependency
# on fuzz-% would start a new campaign, because every target is phony.
coverage: $(COVERAGE_TARGETS)
$(COVERAGE_TARGETS): coverage-%:
	$(RUN) --class replay --key $* --output workspace/reports/coverage/$*.json -- \
		$(PY) $(S)/run_eacsl_fuzz.py coverage --module $* --sources $(SOURCES_$*) \
		--out-bin workspace/harnesses/cov_$* --corpus-dir workspace/corpus/$* \
		--scratch-dir workspace/coverage/$* \
		--cppflags=$(CPPFLAGS_$*) --ldflags=$(LDFLAGS_$*) \
		--out-json workspace/reports/coverage/$*.json

# One Eva run per module, from the harness's eva_main.
eva: $(EVA_TARGETS)
$(EVA_TARGETS): eva-%:
	$(RUN) --class eva --key $* --output workspace/reports/eva/$*.json -- \
		$(PY) $(S)/run_eva_slice.py --module $* --sources $(SOURCES_$*) --main eva_main \
		--out-dir workspace/eva/$* --slevel $(EVA_SLEVEL_$*) $(if $(EVA_MLEVEL_$*),--mlevel $(EVA_MLEVEL_$*)) \
		$(if $(EVA_TAINT_$*),--extra-domains taint) \
		$(if $(EVA_RECURSION_FALLBACK_$*),--allow-incomplete-recursion-specs) \
		$(if $(EVA_TIMEOUT_$*),--timeout $(EVA_TIMEOUT_$*)) \
		--cppflags=$(CPPFLAGS_$*) --out-json workspace/reports/eva/$*.json

# --- Ingestion and Phase 3 preparation -------------------------------------------------------

# New reports only, fuzz before Eva; an expected module without a report is stubbed as not_run
# first. Then validates the run directory.
ingest:
	$(RUN) --class light --key ingest -- $(PM) ingest

# Replays every unverified candidate's reproducers for the crash verifiers (one report per
# candidate, indexed by index.json).
replay: ingest
	$(RUN) --class replay --key candidates --output workspace/reports/replay/index.json -- \
		$(PY) $(S)/run_eacsl_fuzz.py replay-candidates --candidates candidates.json \
		--harness-dir workspace/harnesses --out-dir workspace/reports/replay

wp-queue: ingest
	$(RUN) --class light --key wp-queue -- $(PY) $(S)/wp_scheduler.py init

# --- Phase 4 ---------------------------------------------------------------------------------

# Trusted re-proof of every WP-covered function on the final tree, without the per-run WP cache.
# Not leased itself: pipeline_make.py only coordinates, and leases one `wp` job per function.
wp-sweep:
	$(PM) sweep

report:
	$(RUN) --class light --key report -- $(PY) $(S)/workspace_overlay.py export-diff
	$(RUN) --class light --key report -- $(PY) $(S)/validate_artifacts.py run-dir .
	$(RUN) --class light --key report -- $(PY) $(S)/generate_report.py

# --- Harness-repair loop ---------------------------------------------------------------------

# module-<mod>: the module's own fuzz (with its build) and Eva targets, then ingestion of its
# reports only.
$(foreach m,$(MODULES),$(eval module-$(m): $(filter fuzz-$(m) eva-$(m),$(FUZZ_TARGETS) $(EVA_TARGETS))))
$(MODULE_TARGETS): module-%:
	$(RUN) --class light --key ingest -- $(PM) ingest --module $*
