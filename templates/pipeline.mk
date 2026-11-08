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
# Phase 0 gate stamp check (phase0_gates.py): a recipe that consumes harnesses runs it first, so it
# stops with the reason when the module failed the reach gate or build-check (or they never ran).
GATE := $(PY) $(S)/phase0_gates.py check
SELFTEST_JSON := workspace/reports/eacsl_selftest.json

BUILD_TARGETS  := $(addprefix build-,$(FUZZ_MODULES))
FUZZ_TARGETS   := $(addprefix fuzz-,$(FUZZ_MODULES))
COVERAGE_TARGETS := $(addprefix coverage-,$(FUZZ_MODULES))
REACH_DYNAMIC_TARGETS := $(addprefix reach-dynamic-,$(FUZZ_MODULES))
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
.PHONY: help slice-init reach-gate reach-dynamic seeds seed build selftest fuzz coverage eva eva-tune eva-tune-base flamegraph facts ingest replay minimize wp-queue wp-baseline wp-sweep report \
        $(BUILD_TARGETS) $(FUZZ_TARGETS) $(COVERAGE_TARGETS) $(REACH_DYNAMIC_TARGETS) $(EVA_TARGETS) $(EVA_BASE_TARGETS) $(EVA_RUNG_TARGETS) $(EVA_TUNE_TARGETS) \
        $(FLAMEGRAPH_TARGETS) $(FACTS_TARGETS) $(MODULE_TARGETS)

help:
	@echo 'Targets: slice-init reach-gate seed seeds build selftest fuzz coverage reach-dynamic eva eva-tune flamegraph facts ingest replay minimize wp-queue wp-baseline wp-sweep report module-<mod>'
	@echo 'Fuzz modules: $(FUZZ_MODULES)'
	@echo 'Eva modules: $(EVA_MODULES)'

# --- Phase 0 ---------------------------------------------------------------------------------

# Shadow overlay of the read-only target, then the call-graph DAG of the work tree.
slice-init:
	$(RUN) --class light --key slice-init -- $(PY) $(S)/workspace_overlay.py init --target $(TARGET_DIR) --overlay workspace
	$(RUN) --class light --key slice-init -- $(PY) $(S)/build_callgraph_dag.py --target workspace/work \
		--out workspace/reports/callgraph_dag.json --emit-compile-commands workspace/reports/compile_commands.json

# Phase 0 gate: every DAG entry point of each harnessed module is reached by its harness, or exempted
# with a reason (harness_reach.py exempt). It records workspace/reports/phase0_gates.json.
reach-gate:
	$(RUN) --class light --key reach-gate -- $(PY) $(S)/harness_reach.py check

# Ledger seed (scope paths from run-metadata.json), validation, checkpoint of phase 0. The
# checkpoint is initialized only once, so seeding again never rewinds the recorded progress.
seed: reach-gate
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
	$(GATE) --module $* --need reach
	$(RUN) --class build --key $* --output workspace/build/$*.build.json -- \
		$(PY) $(S)/run_eacsl_fuzz.py build --module $* --sources $(SOURCES_$*) \
		--out-bin workspace/harnesses/fuzz_$* --cppflags=$(CPPFLAGS_$*) --ldflags=$(LDFLAGS_$*) \
		$(if $(FUZZ_NO_RTE_INIT_$*),--no-rte-initialized) \
		--engine=$(FUZZ_ENGINE_$*) \
		--selftest-json $(SELFTEST_JSON) --out-json workspace/build/$*.build.json

# The E-ACSL toolchain canary (runs a compiled canary, so dynamic).
selftest:
	$(RUN) --class selftest --key selftest --output $(SELFTEST_JSON) -- \
		$(PY) $(S)/run_eacsl_fuzz.py selftest --out-json $(SELFTEST_JSON)

# Seed inputs recorded from the target's tests (seed_harvest.py record, run in the build image after
# the build capture) in each harness's case format: workspace/seeds/<mod>/. Rewritten from the records
# before every campaign, so a repaired harness gets seeds in its new format. Seeds are an improvement,
# never a requirement, hence the `-`.
seeds:
	-$(RUN) --class light --key seeds -- $(PY) $(S)/seed_harvest.py write

# One campaign per module. Its effort is a CPU-second budget spread over the workers the lease
# allows (pipeline_make.py: per harness case, capped per unit and profile); FUZZ_MAX_TIME_<mod>
# overrides the wall time. The module's seeds are a read-only extra corpus.
fuzz: $(FUZZ_TARGETS)
$(FUZZ_TARGETS): fuzz-%: selftest build-%
	$(GATE) --module $* --need reach,build_check
	-$(RUN) --class light --key $* -- $(PY) $(S)/seed_harvest.py write --module $*
	$(RUN) --class fuzz --key $* --output workspace/reports/fuzz/$*.json -- \
		$(PY) $(S)/run_eacsl_fuzz.py campaign --module $* --sources $(SOURCES_$*) \
		--out-bin workspace/harnesses/fuzz_$* --corpus-dir workspace/corpus/$* --artifacts-dir workspace/crashes/$* \
		--extra-corpus workspace/seeds/$* \
		--workers auto --fuzz-budget $(FUZZ_BUDGET_$*) \
		$(if $(FUZZ_MAX_TIME_$*),--max-time $(FUZZ_MAX_TIME_$*)) $(if $(FUZZ_DICT_$*),--dict=$(FUZZ_DICT_$*)) \
		$(if $(FUZZ_NO_RTE_INIT_$*),--no-rte-initialized) \
		--engine=$(FUZZ_ENGINE_$*) \
		--cppflags=$(CPPFLAGS_$*) --ldflags=$(LDFLAGS_$*) \
		--selftest-json $(SELFTEST_JSON) --out-json workspace/reports/fuzz/$*.json

# Which functions each module's corpus executes. It replays the corpus as it stands: a dependency
# on fuzz-% would start a new campaign, because every target is phony.
coverage: $(COVERAGE_TARGETS)
$(COVERAGE_TARGETS): coverage-%:
	$(GATE) --module $* --need reach
	$(RUN) --class replay --key $* --output workspace/reports/coverage/$*.json -- \
		$(PY) $(S)/run_eacsl_fuzz.py coverage --module $* --sources $(SOURCES_$*) \
		--out-bin workspace/harnesses/cov_$* --corpus-dir workspace/corpus/$* \
		--extra-corpus workspace/seeds/$* \
		--scratch-dir workspace/coverage/$* \
		--cppflags=$(CPPFLAGS_$*) --ldflags=$(LDFLAGS_$*) \
		--out-json workspace/reports/coverage/$*.json

# Dynamic reach gate: after coverage-<mod>, an API entry point of the module that its corpus never
# executed reopens the reach gate (phase0_gates.json), so fuzz-<mod> and Eva stop until the parent
# repairs the harness or exempts the entry point (`reach-gate` keeps the gap while the harness is unchanged).
reach-dynamic: $(REACH_DYNAMIC_TARGETS)
$(REACH_DYNAMIC_TARGETS): reach-dynamic-%: coverage-%
	$(RUN) --class light --key reach-dynamic -- $(PY) $(S)/harness_reach.py dynamic --module $*

# What every Eva run of module $(1) has in common: the rest is tuning, and tuning never changes what
# is checked, so runs differing only in that can be compared and combined (eva_tuning.py).
eva_args = --module $(1) --sources $(SOURCES_$(1)) --main eva_main --slevel $(EVA_SLEVEL_$(1)) \
	$(if $(EVA_MLEVEL_$(1)),--mlevel $(EVA_MLEVEL_$(1))) \
	$(if $(EVA_TAINT_$(1)),--extra-domains taint) \
	$(if $(EVA_RECURSION_FALLBACK_$(1)),--allow-incomplete-recursion-specs) \
	--no-warn-unsigned-downcast \
	--cppflags=$(CPPFLAGS_$(1))

# The tuning decision of module $(1): its finished base run and rungs, the recorded loop trials and the
# per-obligation combination (eva_tuning.py finish). It writes the module's report, and copies the
# flamegraph.txt of the run the report rests on to workspace/eva/$(1)/.
eva_finish_cmd = $(PY) $(S)/eva_tuning.py finish $(call eva_args,$(1)) \
	$(if $(ENTRY_FN_$(1)),--entry-fn=$(ENTRY_FN_$(1))) \
	--settings-digest $(EVA_TUNE_DIGEST_$(1)) --rungs $(EVA_TUNE_RUNGS_$(1)) --loop-unroll $(EVA_LOOP_UNROLL_$(1)) \
	$(if $(EVA_TUNE_TIMEOUT_$(1)),--timeout $(EVA_TUNE_TIMEOUT_$(1))) \
	--report-dir workspace/reports/eva-tuning/$(1) --work-dir workspace/eva/$(1)/tune \
	--flamegraph-out workspace/eva/$(1)/flamegraph.txt \
	--out-json workspace/reports/eva/$(1).json

# One Eva run per module, from the harness's eva_main. A module with a current tuning decision
# (EVA_REPLAY_<mod>) replays it instead: its base run and recorded rungs (cached by content), then
# `finish --replay-only`, so its report is the one `eva-tune` writes, never a single less precise run.
# A decision found stale against the new base run gives the base run's report and is not re-recorded.
eva_plain_cmd = $(PY) $(S)/run_eva_slice.py $(call eva_args,$(1)) --out-dir workspace/eva/$(1) \
	$(EVA_OPTIONS_$(1)) $(EVA_LOOPS_$(1)) \
	$(if $(EVA_TIMEOUT_$(1)),--timeout $(EVA_TIMEOUT_$(1))) \
	--out-json workspace/reports/eva/$(1).json
eva: $(EVA_TARGETS)
$(foreach m,$(EVA_MODULES),$(if $(EVA_REPLAY_$(m)),$(eval eva-$(m): evabase-$(m) $(foreach r,$(EVA_TUNE_RUNGS_$(m)),evarung-$(m)--$(r)))))
$(EVA_TARGETS): eva-%:
	$(GATE) --module $* --need reach
	$(RUN) --class eva --key $* --output workspace/reports/eva/$*.json -- \
		$(if $(EVA_REPLAY_$*),$(call eva_finish_cmd,$*) --replay-only,$(call eva_plain_cmd,$*))

# Eva ladder: the module's own settings first; `pipeline_make.py run` then regenerates modules.mk, so
# only modules left with Unknowns get rungs. A rung is optional, so a failed one never blocks `finish`,
# which writes the module's report and records the decision in params.json.
eva-tune-base: $(EVA_BASE_TARGETS)
$(EVA_BASE_TARGETS): evabase-%:
	$(GATE) --module $* --need reach
	@rm -f workspace/reports/eva-tuning/$*/base.json
	$(RUN) --class eva --key $* --output workspace/reports/eva-tuning/$*/base.json -- \
		$(PY) $(S)/run_eva_slice.py $(call eva_args,$*) --out-dir workspace/eva/$*/tune/base \
		$(EVA_BASE_OPTIONS_$*) \
		$(if $(EVA_TIMEOUT_$*),--timeout $(EVA_TIMEOUT_$*)) \
		--out-json workspace/reports/eva-tuning/$*/base.json

define EVA_RUNG_RULE
evarung-$(1)--$(2):
	$$(GATE) --module $(1) --need reach
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
	$(GATE) --module $* --need reach
	$(RUN) --class eva --key $* --output workspace/reports/eva/$*.json -- \
		$(call eva_finish_cmd,$*)

# Render the Eva flamegraph (flamegraph.svg/html) of a module from the workspace/eva/<mod>/flamegraph.txt
# its last eva-<mod> or eva-tune left. It never runs Eva (that would replace the module's report), so it
# fails when there is no flamegraph.txt yet. Rendering is a troubleshooting aid, hence the `-`.
flamegraph: $(FLAMEGRAPH_TARGETS)
$(FLAMEGRAPH_TARGETS): flamegraph-%:
	@test -f workspace/eva/$*/flamegraph.txt || { \
		echo "flamegraph-$*: workspace/eva/$*/flamegraph.txt not found: run eva-$* or eva-tune first" >&2; exit 1; }
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

# Phases 1 and 2 are done once the Phase-3 queue is built from their ingested reports: record it,
# so a resumed run starts at Phase 3.
wp-queue: ingest facts
	$(GATE) --need reach,build_check
	$(RUN) --class light --key wp-queue -- $(PY) $(S)/wp_scheduler.py init
	$(RUN) --class light --key wp-queue -- $(PY) $(S)/checkpoint.py save-phase state --phase 2 \
		--from-file workspace/reports/wp_queue.json

# Mechanical Phase-3 WP baseline wave across all queued functions.
# Not leased itself: wp_scheduler.py only coordinates, and leases one `wp` job per function.
wp-baseline: wp-queue
	$(PY) $(S)/wp_scheduler.py baseline

# --- Phase 4 ---------------------------------------------------------------------------------

# Trusted re-proof of every WP-covered function on the final tree, without the per-run WP cache.
# Not leased itself: pipeline_make.py only coordinates, and leases one `wp` job per function.
wp-sweep:
	$(PM) sweep

# The hypothesis audit runs first, so the report never shows a caller as unconditionally proven
# while a callee below it is not.
report:
	$(RUN) --class light --key report -- $(PY) $(S)/ledger.py audit-hypotheses
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
