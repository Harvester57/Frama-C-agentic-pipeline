# syntax=docker/dockerfile:1
FROM framac/frama-c:dev@sha256:89ab2bd8e8a133ede99257c0403a2752c872bf2861e1a15911279a322da69cdd

LABEL maintainer="Frama-C Agentic Verification Pipeline"
LABEL description="Self-contained Frama-C (RTE, Eva, WP, E-ACSL, Mdr/SARIF) + SMT Solvers (Alt-Ergo, Z3, CVC5) + Clang/LibFuzzer + Bear container"

USER root
ENV HOME=/home/opam
ENV DEBIAN_FRONTEND=noninteractive
ENV OPAMYES=1
ENV OPAMROOT=/home/opam/.opam
ENV PYTHONIOENCODING=utf-8
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8
ENV PATH="/home/opam/.opam/5.5/bin:${PATH}"
ENV FRAMAC_SHARE="/home/opam/.opam/5.5/share/frama-c"
ENV WHY3CONFIG="/home/opam/.why3.conf"
ENV S="/opt/framac-pipeline/scripts"

# Install system dependencies, Clang + LibFuzzer, Bear, and SMT solvers (Z3, CVC5)
RUN apt-get update && apt-get install -y --no-install-recommends \
    autoconf \
    automake \
    bear \
    build-essential \
    ca-certificates \
    clang \
    cmake \
    curl \
    cvc5 \
    git \
    graphviz \
    jq \
    libbsd-dev \
    libclang-rt-dev \
    libevent-dev \
    libgmp-dev \
    libjson-c-dev \
    libmpfr-dev \
    libpcap-dev \
    libsnmp-dev \
    libsqlite3-dev \
    libssl-dev \
    libxml2-dev \
    llvm \
    m4 \
    ninja-build \
    pkg-config \
    python3 \
    python3-pip \
    python3-venv \
    time \
    unzip \
    wget \
    z3 \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/* \
    && chmod a+rx /home/opam /root \
    && chmod -R a+rX /home/opam/.opam \
    && printf 'export PATH="/home/opam/.opam/5.5/bin:${PATH}"\nexport FRAMAC_SHARE="/home/opam/.opam/5.5/share/frama-c"\nexport WHY3CONFIG="/home/opam/.why3.conf"\n' > /etc/profile.d/framac.sh \
    && chmod 644 /etc/profile.d/framac.sh \
    && python3 -c "from pathlib import Path; p = Path('/home/opam/.opam/5.5/share/why3/provers-detection-data.conf'); p.write_text(p.read_text().replace(')$', ')'))" \
    && why3 config detect -C /home/opam/.why3.conf \
    && cp -f /home/opam/.why3.conf /root/.why3.conf \
    && chmod 644 /home/opam/.why3.conf /root/.why3.conf

# Optional target-specific apt packages (built via --target-packages / -TargetPackages before dropping capabilities)
ARG TARGET_APT_PACKAGES=""
RUN if [ -n "${TARGET_APT_PACKAGES}" ]; then \
        apt-get update && \
        apt-get install -y --no-install-recommends ${TARGET_APT_PACKAGES} && \
        rm -rf /var/lib/apt/lists/*; \
    fi

# Copy pipeline scripts, templates, schemas, and skills into /opt/framac-pipeline for container-internal access
COPY scripts/ /opt/framac-pipeline/scripts/
COPY templates/ /opt/framac-pipeline/templates/
COPY schemas/ /opt/framac-pipeline/schemas/
COPY skills/ /opt/framac-pipeline/skills/
RUN chmod +x /opt/framac-pipeline/scripts/*.py /opt/framac-pipeline/scripts/*.sh

WORKDIR /framac-run

ENTRYPOINT ["/bin/bash", "-lc"]
