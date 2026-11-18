#!/bin/bash
# What the Frama-C kernel reads inside an ACSL annotation: comments, nested `//@`, `@`, literals and
# backslash line ends. The *.c files beside this script are the inputs and the *.log files are what
# framac-analysis:latest (Frama-C 34.0~beta, image b33b01633608) printed for them on 2026-11-18.
# tests/test_acsl_annotation_comments.py compares scripts/acsl_ast.py with these logs.
#
# Run in the analysis image with this directory mounted read-only on /w:
#   docker run --rm --network none -v "<this directory>:/w:ro" --entrypoint bash framac-analysis:latest /w/scenario.sh
#
# probe.c holds every first-round case. Its case E (a block comment inside a `//@` annotation) aborts
# the parse, so probe2.c is probe.c without cases E and N, and probe_n.c is case N alone.
cd /w || exit 1

# probe.log
frama-c -version
echo "@@ DEFAULT"
frama-c -no-unicode -kernel-warn-key annot-error=active probe.c -print 2>&1
echo "@@ NO-PP-ANNOT"
frama-c -no-unicode -no-pp-annot -kernel-warn-key annot-error=active probe.c -print 2>&1
echo "@@ CPP"
frama-c -no-unicode -kernel-msg-key pp probe.c 2>&1 | head -5

# probe2.log
for f in probe2.c probe_n.c; do
  echo "@@ DEFAULT $f"
  frama-c -no-unicode -pp-annot -kernel-warn-key annot-error=active "$f" -print 2>&1
done
echo "@@ GCC-E probe2.c"
gcc -E -C probe2.c 2>&1 | sed -n "/case_g/,/case_h/p;/G:/,/case_g/p"

# probe3.log
for f in p3a.c p3b.c p3c.c p3d.c p3e.c p3f.c; do
  echo "@@ ACTIVE $f"
  frama-c -no-unicode -pp-annot -kernel-warn-key annot-error=active "$f" -print 2>&1
  echo "rc=$?"
done
for f in p3c.c p3d.c; do
  echo "@@ DEFAULTKEYS $f"
  frama-c -no-unicode -pp-annot "$f" -print 2>&1
  echo "rc=$?"
done
