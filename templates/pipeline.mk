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
EVA_BASE_TARGETS := $(addprefix evabase-,$(EVA_MODULES))
EVA_RUNG_TARGETS := $(foreach m,$(EVA_MODULES),$(foreach r,$(EVA_TUNE_RUNGS_$(m)),evarung-$(m)--$(r)))
EVA_TUNE_TARGETS := $(addprefix evatune-,$(EVA_MODULES))
FLAMEGRAPH_TARGETS := $(addprefix flamegraph-,$(EVA_MODULES))
FACTS_TARGETS  := $(addprefix facts-,$(MODULES))
MODULE_TARGETS := $(addprefix module-,$(MODULES))

MAKEFLAGS += --no-builtin-rules
.SUFFIXES:
.DEFAULT_GOAL := help
.PHONY: help slice-init seed build selftest fuzz coverage eva eva-tune eva-tune-base flamegraph facts ingest replay minimize wp-queue wp-sweep report \
        $(BUILD_TARGETS) $(FUZZ_TARGETS) $(COVERAGE_TARGETS) $(EVA_TARGETS) $(EVA_BASE_TARGETS) $(EVA_RUNG_TARGETS) $(EVA_TUNE_TARGETS) \
        $(FLAMEGRAPH_TARGETS) $(FACTS_TARGETS) $(MODULE_TARGETS)

help:
	@echo 'Targets: slice-init seed build selftest fuzz coverage eva eva-tune flamegraph facts ingest replay minimize wp-queue wp-sweep report module-<mod>'
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

# What every Eva run of module $(1) has in common: the rest is tuning, and tuning never changes what
# is checked, so runs differing only in that can be compared and combined (eva_tuning.py).
eva_args = --module $(1) --sources $(SOURCES_$(1)) --main eva_main --slevel $(EVA_SLEVEL_$(1)) \
	$(if $(EVA_MLEVEL_$(1)),--mlevel $(EVA_MLEVEL_$(1))) \
	$(if $(EVA_TAINT_$(1)),--extra-domains taint) \
	$(if $(EVA_RECURSION_FALLBACK_$(1)),--allow-incomplete-recursion-specs) \
	--cppflags=$(CPPFLAGS_$(1))

# One Eva run per module, from the harness's eva_main, with its recorded tuning if it has one.
eva: $(EVA_TARGETS)
$(EVA_TARGETS): eva-%:
	$(RUN) --class eva --key $* --output workspace/reports/eva/$*.json -- \
		$(PY) $(S)/run_eva_slice.py $(call eva_args,$*) --out-dir workspace/eva/$* \
		$(EVA_OPTIONS_$*) $(EVA_LOOPS_$*) \
		$(if $(EVA_TIMEOUT_$*),--timeout $(EVA_TIMEOUT_$*)) \
		--out-json workspace/reports/eva/$*.json

# Eva ladder: the module's own settings first; `pipeline_make.py run` then regenerates modules.mk, so
# only modules left with Unknowns get rungs. A rung is optional, so a failed one never blocks `finish`,
# which writes the module's report and records the decision in params.json.
eva-tune-base: $(EVA_BASE_TARGETS)
$(EVA_BASE_TARGETS): evabase-%:
	@rm -f workspace/reports/eva-tuning/$*/base.json
	$(RUN) --class eva --key $* --output workspace/reports/eva-tuning/$*/base.json -- \
		$(PY) $(S)/run_eva_slice.py $(call eva_args,$*) --out-dir workspace/eva/$*/tune/base \
		$(EVA_BASE_OPTIONS_$*) \
		$(if $(EVA_TIMEOUT_$*),--timeout $(EVA_TIMEOUT_$*)) \
		--out-json workspace/reports/eva-tuning/$*/base.json

define EVA_RUNG_RULE
evarung-$(1)--$(2):
	@rm -f workspace/reports/eva-tuning/$(1)/$(2).json
	-$$(RUN) --class eva --key $(1) --output workspace/reports/eva-tuning/$(1)/$(2).json -- \
		$$(PY) $$(S)/run_eva_slice.py $$(call eva_args,$(1)) --out-dir workspace/eva/$(1)/tune/$(2) \
		$$(EVA_RUNG_OPTIONS_$(1)__$(2)) \
		$$(if $$(EVA_TUNE_TIMEOUT_$(1)),--timeout $$(EVA_TUNE_TIMEOUT_$(1))) \
		--out-json workspace/reports/eva-tuning/$(1)/$(2).json
endef
$(foreach m,$(EVA_MODULES),$(foreach r,$(EVA_TUNE_RUNGS_$(m)),$(eval $(call EVA_RUNG_RULE,$(m),$(r)))))

eva-tune: $(EVA_TUNE_TARGETS)
$(foreach m,$(EVA_MODULES),$(eval evatune-$(m): $(foreach r,$(EVA_TUNE_RUNGS_$(m)),evarung-$(m)--$(r))))
$(EVA_TUNE_TARGETS): evatune-%:
	$(RUN) --class eva --key $* --output workspace/reports/eva/$*.json -- \
		$(PY) $(S)/eva_tuning.py finish $(call eva_args,$*) \
		$(if $(ENTRY_FN_$*),--entry-fn=$(ENTRY_FN_$*)) \
		--settings-digest $(EVA_TUNE_DIGEST_$*) --rungs $(EVA_TUNE_RUNGS_$*) --loop-unroll $(EVA_LOOP_UNROLL_$*) \
		$(if $(EVA_TUNE_TIMEOUT_$*),--timeout $(EVA_TUNE_TIMEOUT_$*)) \
		--report-dir workspace/reports/eva-tuning/$* --work-dir workspace/eva/$*/tune \
		--out-json workspace/reports/eva/$*.json

# Render the Eva flamegraph (flamegraph.svg/html) of a module from the flamegraph.txt its eva-<mod>
# run wrote. Troubleshooting aid for slow runs; never blocks the pipeline, hence the `-`.
flamegraph: $(FLAMEGRAPH_TARGETS)
$(FLAMEGRAPH_TARGETS): flamegraph-%: eva-%
	-$(RUN) --class light --key $* --output workspace/eva/$*/flamegraph.svg -- \
		$(PY) $(S)/eva_flamegraph.py --dir workspace/eva/$*

# Kernel AST facts of the module's functions, joined with the flows of its Eva report if there is
# one, for the provers' briefs (cached by content). Hints only: a failure means briefs without
# facts, never a stopped pipeline, hence the `-`.
facts: $(FACTS_TARGETS)
$(FACTS_TARGETS): facts-%:
	-$(RUN) --class eva --key $* --output workspace/reports/facts/$*.json -- \
		$(PY) $(S)/function_facts.py --module $* --sources $(SOURCES_$*) --cppflags=$(CPPFLAGS_$*) \
		--eva-report workspace/reports/eva/$*.json --out-json workspace/reports/facts/$*.json

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

# Minimizes every unverified candidate's reproducer with cvise/creduce (writes <artifact>.min next
# to each crash input; indexed by workspace/reports/minimize/index.json). Best run after `replay`;
# skipped cleanly when cvise is not installed (tool_unavailable).
minimize: replay
	-$(RUN) --class replay --key minimize --output workspace/reports/minimize/index.json -- \
		$(PY) $(S)/run_eacsl_fuzz.py minimize-candidates --candidates candidates.json \
		--harness-dir workspace/harnesses --out-dir workspace/reports/minimize

wp-queue: ingest facts
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
# reports only, then its facts from the new Eva report.
$(foreach m,$(MODULES),$(eval module-$(m): $(filter fuzz-$(m) eva-$(m),$(FUZZ_TARGETS) $(EVA_TARGETS))))
$(MODULE_TARGETS): module-%:
	$(RUN) --class light --key ingest -- $(PM) ingest --module $*
	-$(RUN) --class eva --key $* --output workspace/reports/facts/$*.json -- \
		$(PY) $(S)/function_facts.py --module $* --sources $(SOURCES_$*) --cppflags=$(CPPFLAGS_$*) \
		--eva-report workspace/reports/eva/$*.json --out-json workspace/reports/facts/$*.json
