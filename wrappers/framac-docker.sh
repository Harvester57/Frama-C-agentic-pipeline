#!/usr/bin/env bash
# Executes a command inside the hardened framac-pipeline container.
#
#   framac-docker.sh [--target DIR] (--run-dir DIR | --new-run) [--repo NAME]
#                    [--target-packages "pkg1 pkg2"] [--build-if-missing]
#                    [--no-inner-sandbox] [--allow-degraded-sandbox]
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
DEFAULT_CPUS="$(command -v nproc >/dev/null 2>&1 && nproc || echo 4)"
DEFAULT_MEM="$(awk '/MemTotal:/ { g = int(($2 / 1048576) * 0.75); if (g < 8) g = 8; print g "g" }' /proc/meminfo 2>/dev/null || echo 8g)"
[[ -z "${DEFAULT_MEM}" ]] && DEFAULT_MEM="8g"
CPUS="${FRAMAC_CPUS:-${DEFAULT_CPUS}}"
MEMORY="${FRAMAC_MEMORY:-${DEFAULT_MEM}}"
PIDS="${FRAMAC_PIDS_LIMIT:-4096}"
RUN_DIR=""
NEW_RUN=0
REPO=""
TARGET_PACKAGES=""
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
        --target-packages) TARGET_PACKAGES="$2"; shift 2 ;;
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

if [[ -n "${TARGET_PACKAGES}" ]]; then
    DERIVED_IMAGE="framac-pipeline:${REPO}"
    echo "[framac-docker] Building derived image ${DERIVED_IMAGE} with target packages: ${TARGET_PACKAGES}" >&2
    docker build -t "${DERIVED_IMAGE}" --build-arg "TARGET_APT_PACKAGES=${TARGET_PACKAGES}" "${PIPELINE_ROOT}"
    IMAGE="${DERIVED_IMAGE}"
fi

RUN_ID="$(basename "${RESOLVED_RUN}")"
TARGET_COMMIT="$(git -C "${RESOLVED_TARGET}" rev-parse HEAD 2>/dev/null || true)"
TARGET_DIRTY=""
if [[ -n "${TARGET_COMMIT}" ]]; then
    if [[ -n "$(git -C "${RESOLVED_TARGET}" status --porcelain --untracked-files=no 2>/dev/null || true)" ]]; then
        TARGET_DIRTY="1"
    else
        TARGET_DIRTY="0"
    fi
fi

ARGS=(run --rm -i --network none --cap-drop ALL --security-opt no-new-privileges
      --cpus "${CPUS}" --memory "${MEMORY}" --pids-limit "${PIDS}")
[[ ${INNER} -eq 1 ]] && ARGS+=(--security-opt seccomp=unconfined --security-opt apparmor=unconfined)
ARGS+=(-e PYTHONIOENCODING=utf-8 -e FRAMAC_OUTER_SANDBOX=docker-hardened
       -e "FRAMAC_TARGET_HOST=${RESOLVED_TARGET}" -e "FRAMAC_REPO=${REPO}"
       -e "FRAMAC_RUN_ID=${RUN_ID}"
       -e "FRAMAC_TARGET_COMMIT=${TARGET_COMMIT}"
       -e "FRAMAC_TARGET_DIRTY=${TARGET_DIRTY}")
[[ ${DEGRADED} -eq 1 ]] && ARGS+=(-e FRAMAC_SANDBOX_DEGRADED=1)
ARGS+=(-v "${RESOLVED_TARGET}:/target:ro"
       -v "${RESOLVED_RUN}:/framac-run"
       -v "${PIPELINE_ROOT}/scripts:/opt/framac-pipeline/scripts:ro"
       -v "${PIPELINE_ROOT}/templates:/opt/framac-pipeline/templates:ro"
       -v "${PIPELINE_ROOT}/schemas:/opt/framac-pipeline/schemas:ro"
       -w /framac-run "${IMAGE}" "$*")

exec docker "${ARGS[@]}"
