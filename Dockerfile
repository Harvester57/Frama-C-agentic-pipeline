# syntax=docker/dockerfile:1
#
# Two images from one file (docs/plans/archive/phase0-implementation-plan.md, decision "Images"); the optional third
# image has its own Dockerfile:
#   docker build --target framac-analysis -t framac-analysis .     Frama-C, provers, instrumented builds
#   docker build --target framac-build -t framac-build .           the target's build and tests
# The build and analysis images share the Debian release, gcc and glibc (checked by
# scripts/image_toolchain.py), so flags captured in one mean the same in the other and binaries
# link against the same libc. The analysis image is the last stage, so a build without --target makes it.
#
# The "common base stage" of the plan's decision "Images" (remediation plan step R8, decision D9): both
# images start from the same pinned Debian image (DEBIAN_BASE). Frama-C, its provers and MetAcsl are built
# from source in an opam stage (framac-opam, on the official OCaml image OPAM_BASE, the same Debian
# release) and only the opam switch is copied into the analysis image. Both bases are pinned digests: bump them together;
# CI's toolchain check (image_toolchain.py compare) fails when the release, gcc or glibc drift apart.
#
# Frama-C and MetAcsl come from the local opam repository in opam/ (opam files of their pending
# opam-repository releases, ocaml/opam-repository#31236 and #31235, each with its source checksum
# and a curated source-only patch queue managed by tools/sync_opam_patches.py).
# Every other package comes from the opam-repository checkout inside OPAM_BASE, so the digest pins it.
#
# Both images create /framac-scratch and /framac-cache, mode 1777: a new named scratch volume (or a named
# cache volume) mounted there copies that mode on its first mount, so any non-root uid can write the
# capture's scratch tree (or the shared cache) without a chmod step.
ARG OPAM_BASE=ocaml/opam:debian-13-ocaml-5.5@sha256:2f2870cc00eb7f66d39715193466107a3f1abd71fed09f078505b02bb21488dd
ARG FRAMAC_VERSION=34.0~beta
ARG METACSL_VERSION=0.12~beta
# Debian 13 (trixie): the build image, the opam stage's release and the analysis image's base.
ARG DEBIAN_BASE=debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

# --- Build image: runs the target's own build and its tests ----------------------------------------
FROM ${DEBIAN_BASE} AS framac-build

LABEL description="Frama-C pipeline build image: the target's build (make, CMake, Meson, Ninja, autotools under bear) and its tests (strace), with common -dev libraries"

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONIOENCODING=utf-8
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8
ENV HOME=/home/framac
ENV S="/opt/framac-pipeline/scripts"

RUN apt-get update && apt-get install -y --no-install-recommends \
    autoconf \
    automake \
    bear \
    build-essential \
    ca-certificates \
    clang \
    cmake \
    curl \
    file \
    git \
    jq \
    libbsd-dev \
    libevent-dev \
    libjson-c-dev \
    libpcap-dev \
    libsnmp-dev \
    libsqlite3-dev \
    libssl-dev \
    libtool \
    libxml2-dev \
    m4 \
    meson \
    ninja-build \
    pkg-config \
    python3 \
    strace \
    time \
    zlib1g-dev \
    zstd \
    && rm -rf /var/lib/apt/lists/*

# Target packages (a derived image per target, framac-build:<repo>).
ARG TARGET_APT_PACKAGES=""
RUN if [ -n "${TARGET_APT_PACKAGES}" ]; then \
        apt-get update && \
        apt-get install -y --no-install-recommends ${TARGET_APT_PACKAGES} && \
        rm -rf /var/lib/apt/lists/*; \
    fi

COPY scripts/ /opt/framac-pipeline/scripts/
COPY templates/ /opt/framac-pipeline/templates/
COPY schemas/ /opt/framac-pipeline/schemas/
RUN chmod -R a+rX /opt/framac-pipeline \
    && chmod a+x /opt/framac-pipeline/scripts/*.py /opt/framac-pipeline/scripts/*.sh \
    && mkdir -p /home/framac/.cache /framac-run /framac-scratch /framac-cache \
    && chmod 1777 /home/framac /home/framac/.cache /framac-run /framac-scratch /framac-cache

WORKDIR /framac-run
ENTRYPOINT ["/bin/bash", "-lc"]

# --- opam stage: Frama-C, MetAcsl, Why3 and Alt-Ergo built from source into the switch -------------
FROM ${OPAM_BASE} AS framac-opam

USER opam
ENV OPAMYES=1
ENV OPAMCONFIRMLEVEL=unsafe-yes
ARG FRAMAC_VERSION
ARG METACSL_VERSION
COPY --chown=opam:opam opam/ /home/opam/framac-opam-repo/
# No `opam update`: the default repository stays the checkout pinned by OPAM_BASE. Depexts (GMP, zlib,
# graphviz) come from apt through opam. The switch is then stripped of what a job never reads.
RUN opam repo add --this-switch framac-local /home/opam/framac-opam-repo \
    && opam install "frama-c.${FRAMAC_VERSION}" "frama-c-metacsl.${METACSL_VERSION}" \
        why3.1.8.2 alt-ergo-free.2.4.3 ocamlfind \
    && cp /home/opam/framac-opam-repo/patches-manifest.json \
        /home/opam/.opam/5.5/share/frama-c/pipeline-patches.json \
    && opam exec -- frama-c -version \
    && opam exec -- frama-c -plugins | grep -q MetAcsl \
    && opam clean --all-switches --download-cache --logs --repo-cache \
    && rm -rf /home/opam/.opam/5.5/.opam-switch/sources /home/opam/.opam/5.5/.opam-switch/build \
        /home/opam/.opam/5.5/doc /home/opam/.opam/5.5/man

# --- Analysis image: Frama-C, provers, instrumented builds; no build systems, no target packages ------
FROM ${DEBIAN_BASE} AS framac-analysis

LABEL description="Frama-C pipeline analysis image: Frama-C (RTE, Eva, WP, E-ACSL, MetAcsl), Alt-Ergo, Z3, CVC5, Clang/LibFuzzer, cvise; the target's headers and libraries come from the build image's snapshot"

ENV HOME=/home/opam
ENV DEBIAN_FRONTEND=noninteractive
ENV OPAMROOT=/home/opam/.opam
ENV PYTHONIOENCODING=utf-8
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8
ENV PATH="/home/opam/.opam/5.5/bin:${PATH}"
ENV FRAMAC_SHARE="/home/opam/.opam/5.5/share/frama-c"
ENV WHY3CONFIG="/home/opam/.why3.conf"
ENV S="/opt/framac-pipeline/scripts"

# The switch only: compiler, ocamlfind (the dump modules are compiled at run time), Frama-C and plug-ins.
COPY --from=framac-opam /home/opam/.opam/5.5 /home/opam/.opam/5.5

# build-essential stays: Frama-C preprocesses with gcc, E-ACSL compiles with it, the dump modules link
# with it, and the pipeline's own Makefile needs make. GMP serves Zarith and, with MPFR, E-ACSL's runtime;
# zlib serves camlzip.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    clang \
    cvc5 \
    cvise \
    git \
    graphviz \
    jq \
    libclang-rt-dev \
    libgmp-dev \
    libmpfr-dev \
    llvm \
    python3 \
    time \
    z3 \
    zlib1g \
    && rm -rf /var/lib/apt/lists/* \
    && chmod a+rx /home/opam /root \
    && chmod -R a+rX /home/opam/.opam \
    && printf 'export PATH="/home/opam/.opam/5.5/bin:${PATH}"\nexport FRAMAC_SHARE="/home/opam/.opam/5.5/share/frama-c"\nexport WHY3CONFIG="/home/opam/.why3.conf"\n' > /etc/profile.d/framac.sh \
    && chmod 644 /etc/profile.d/framac.sh \
    && python3 -c "from pathlib import Path; p = Path('/home/opam/.opam/5.5/share/why3/provers-detection-data.conf'); p.write_text(p.read_text().replace(')$', ')'))" \
    && why3 config detect -C /home/opam/.why3.conf \
    && cp -f /home/opam/.why3.conf /root/.why3.conf \
    && chmod 644 /home/opam/.why3.conf /root/.why3.conf

# MetAcsl (program-wide ACSL properties, Layers 4-6) and the curated patch manifest come with the switch.
RUN frama-c -plugins | grep -q MetAcsl \
    && python3 -c "import json, pathlib; m = json.loads(pathlib.Path('/home/opam/.opam/5.5/share/frama-c/pipeline-patches.json').read_text()); assert m['frama_c'] and m['metacsl'] and m['digest']"

COPY scripts/ /opt/framac-pipeline/scripts/
COPY templates/ /opt/framac-pipeline/templates/
COPY schemas/ /opt/framac-pipeline/schemas/
COPY skills/ /opt/framac-pipeline/skills/
COPY docs/references/ /opt/framac-pipeline/docs/references/
# Jobs run as an arbitrary non-root uid (the wrappers pass --user <host uid>:<host gid>; compose uses
# FRAMAC_UID/FRAMAC_GID): everything they read must be world-readable, and HOME plus the default working
# directory must be writable by any uid (sticky, like /tmp), since that uid has no passwd entry or home.
RUN chmod -R a+rX /opt/framac-pipeline \
    && chmod a+x /opt/framac-pipeline/scripts/*.py /opt/framac-pipeline/scripts/*.sh \
    && mkdir -p /home/opam/.cache /framac-run /framac-scratch /framac-cache \
    && chmod 1777 /home/opam /home/opam/.cache /framac-run /framac-scratch /framac-cache
# The Phase 0 model's dump module must compile and load against this kernel.
RUN python3 /opt/framac-pipeline/scripts/phase0_model.py selftest

WORKDIR /framac-run
ENTRYPOINT ["/bin/bash", "-lc"]
