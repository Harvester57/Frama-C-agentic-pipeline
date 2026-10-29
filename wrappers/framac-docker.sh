#!/usr/bin/env bash
# Executes a command inside the hardened framac-pipeline container.
#
#   framac-docker.sh [--target DIR] (--run-dir DIR | --new-run) [--repo NAME]
#                    [--build-if-missing] [--no-inner-sandbox] [--allow-degraded-sandbox]
#                    [--allow-run-dir-in-target] -- <command...>
#
# Mounts: /target (read-only), /framac-run (run dir, read-write, working dir),
# /opt/framac-pipeline/{scripts,templates,schemas} (read-only).
# Hardening: --network none, --cap-drop ALL, no-new-privileges, cpu/memory/pids limits,
# allowlisted environment. seccomp is relaxed only for bubblewrap's user namespaces
# (inner sandbox, scripts/sandbox_exec.py); --no-inner-sandbox keeps the default profile.
set -euo pipefail

export PYTHONIOENCODING="utf-8"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIPELINE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TARGET_DIR="${TARGET_DIR:-$(pwd)}"
IMAGE="${FRAMAC_DOCKER_IMAGE:-framac-pipeline:latest}"
CPUS="${FRAMAC_CPUS:-4}"
MEMORY="${FRAMAC_MEMORY:-8g}"
PIDS="${FRAMAC_PIDS_LIMIT:-4096}"
RUN_DIR=""
NEW_RUN=0
REPO=""
BUILD=0
INNER=1
DEGRADED=0
ALLOW_IN_TARGET=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target) TARGET_DIR="$2"; shift 2 ;;
        --run-dir) RUN_DIR="$2"; shift 2 ;;
        --new-run) NEW_RUN=1; shift ;;
        --repo) REPO="$2"; shift 2 ;;
        --build-if-missing) BUILD=1; shift ;;
        --no-inner-sandbox) INNER=0; shift ;;
        --allow-degraded-sandbox) DEGRADED=1; shift ;;
        --allow-run-dir-in-target) ALLOW_IN_TARGET=1; shift ;;
        --) shift; break ;;
        *) break ;;
    esac
done

RESOLVED_TARGET="$(cd "${TARGET_DIR}" && pwd)"
REPO="${REPO:-$(basename "${RESOLVED_TARGET}")}"
if [[ ! "${REPO}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
    echo "[framac-docker] invalid repo name '${REPO}' (use --repo)" >&2; exit 2
fi

if [[ ${NEW_RUN} -eq 1 ]]; then
    [[ -n "${RUN_DIR}" ]] && { echo "[framac-docker] use --run-dir or --new-run, not both" >&2; exit 2; }
    BASE="${HOME}/framac-pipeline/${REPO}"
    mkdir -p "${BASE}"
    MAX=0
    for d in "${BASE}"/run-*; do
        [[ -d "$d" ]] || continue
        n="${d##*/run-}"
        [[ "$n" =~ ^[0-9]+$ ]] && (( n > MAX )) && MAX=$n
    done
    RUN_DIR="${BASE}/run-$((MAX + 1))"
fi
[[ -z "${RUN_DIR}" ]] && { echo "[framac-docker] specify --run-dir DIR or --new-run" >&2; exit 2; }
mkdir -p "${RUN_DIR}"
RESOLVED_RUN="$(cd "${RUN_DIR}" && pwd)"

case "${RESOLVED_RUN}/" in
    "${RESOLVED_TARGET}/"*)
        if [[ ${ALLOW_IN_TARGET} -ne 1 ]] || ! git -C "${RESOLVED_TARGET}" check-ignore -q "${RESOLVED_RUN}"; then
            echo "[framac-docker] run dir is inside the target; use an outside path or a git-ignored path with --allow-run-dir-in-target" >&2
            exit 2
        fi ;;
esac
echo "[framac-docker] run dir: ${RESOLVED_RUN}" >&2

if [[ -z "$(docker images -q "${IMAGE}" 2>/dev/null)" ]]; then
    if [[ ${BUILD} -eq 1 ]]; then
        echo "[framac-docker] Building ${IMAGE}..." >&2
        docker build -t "${IMAGE}" "${PIPELINE_ROOT}"
    else
        echo "[framac-docker] image ${IMAGE} not found (use --build-if-missing)" >&2; exit 2
    fi
fi

ARGS=(run --rm -i --network none --cap-drop ALL --security-opt no-new-privileges
      --cpus "${CPUS}" --memory "${MEMORY}" --pids-limit "${PIDS}")
[[ ${INNER} -eq 1 ]] && ARGS+=(--security-opt seccomp=unconfined)
ARGS+=(-e PYTHONIOENCODING=utf-8 -e FRAMAC_OUTER_SANDBOX=docker-hardened
       -e "FRAMAC_TARGET_HOST=${RESOLVED_TARGET}" -e "FRAMAC_REPO=${REPO}")
[[ ${DEGRADED} -eq 1 ]] && ARGS+=(-e FRAMAC_SANDBOX_DEGRADED=1)
ARGS+=(-v "${RESOLVED_TARGET}:/target:ro"
       -v "${RESOLVED_RUN}:/framac-run"
       -v "${PIPELINE_ROOT}/scripts:/opt/framac-pipeline/scripts:ro"
       -v "${PIPELINE_ROOT}/templates:/opt/framac-pipeline/templates:ro"
       -v "${PIPELINE_ROOT}/schemas:/opt/framac-pipeline/schemas:ro"
       -w /framac-run "${IMAGE}" "$*")

exec docker "${ARGS[@]}"
