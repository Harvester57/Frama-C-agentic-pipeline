# syntax=docker/dockerfile:1
#
# framac-codeql:<repo>: a target's derived build image (framac-build:<repo>, with its packages) plus the
# CodeQL CLI and C/C++ packs copied from framac-codeql:latest, which Dockerfile.codeql builds from the
# pinned, digest-checked bundle. Nothing is downloaded here. The wrappers build it from stdin (no context)
# with -CodeQL / --codeql and labels holding both base image ids; it is rebuilt when either changes.
# Local only: never pushed or shared (docs/phase0-implementation-plan.md step I7).
ARG BUILD_IMAGE=framac-build:latest
ARG CODEQL_IMAGE=framac-codeql:latest
FROM ${CODEQL_IMAGE} AS codeql

FROM ${BUILD_IMAGE}
COPY --from=codeql /opt/codeql /opt/codeql
RUN ln -sf /opt/codeql/codeql /usr/local/bin/codeql \
    && codeql version --format=terse
LABEL description="Frama-C pipeline CodeQL image for one target: its build image + CodeQL; local use only" \
      framac.local-only="1"
