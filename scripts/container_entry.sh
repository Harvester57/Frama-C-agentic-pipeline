#!/usr/bin/env bash
# Entry shim of every container started on the wrappers' broker path:
#   <engine> run ... --entrypoint /bin/bash <image> /opt/framac-pipeline/scripts/container_entry.sh "<command>"
# Runs the command string exactly like the image's default entrypoint (bash -lc), then records
# this container's resource usage (cgroup memory.peak, oom_kill count, cpu.stat) under the run's
# state/resource-history/ so the next lease of the same class is sized from what this one used.
# The command's exit status is always preserved; recording output and errors are discarded.
export S="/opt/framac-pipeline/scripts"
rc=0
bash -lc "${1:-}" || rc=$?
python3 /opt/framac-pipeline/scripts/resources.py record --rc "${rc}" >/dev/null 2>&1 || true
exit "${rc}"
