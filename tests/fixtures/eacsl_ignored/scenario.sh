#!/bin/sh
# Docker scenario for tests/test_eacsl_ignored_annotations.py: the captures in this directory.
# Mounts: /fixture (this directory, read-only), /out (writable, receives the captures) and, to run the
# scripts of a checkout instead of the image's, /repo (read-only). In the analysis image:
#   docker run --rm --network none -v <this dir>:/fixture:ro -v <checkout>:/repo:ro -v <out dir>:/out \
#     framac-analysis:latest "sh /fixture/scenario.sh"
# The sources sit at workspace/work/src/, as in a run directory: the logs name them by that path.
# unb_requires.json and violation.json were captured with the scripts of commit ec7c8c7, before the
# guardrail read `Ignoring annotation`: they are the evidence of the bug. A capture with later scripts
# must not replace them (its reports name the ignored clauses).
set -e
mkdir -p /tmp/w/workspace/work/src /tmp/w/workspace/corpus/probe
cd /tmp/w
cp /fixture/probe.c /fixture/probe.h /fixture/violation.c /fixture/extras.c workspace/work/src/
printf 'AB' > workspace/corpus/probe/seed-ab
printf 'hello world 1234' > workspace/corpus/probe/seed-full
export FRAMAC_CACHE=off
timeout 1500 python3 /fixture/capture.py
