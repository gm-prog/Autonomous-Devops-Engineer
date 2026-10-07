# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
# check=skip=InvalidDefaultArgInFrom;error=true

# Phase 8.7-B.0 traffic-topology workload fixture.
#
# Two builds of this file (TRACK=stable, TRACK=canary) produce two
# distinct images with distinct identities, so the stable and canary
# backends differ in image as well as in Deployment -- "genuinely
# distinct workloads" is then observable, not just asserted.
#
# Immutable build input, same policy as e2e/workload/Dockerfile:
# BASE_IMAGE must be a <name>@sha256:<64hex> reference supplied from the
# committed pin file (e2e/pinned-images.txt, key E2E_PYTHON_BASE_IMAGE).
# There is no default: omitting the argument leaves the base name blank
# and BuildKit refuses the build. Compose's required-value operator is
# NOT valid in a Dockerfile parser, so it must never appear here.
ARG BASE_IMAGE
ARG TRACK
FROM ${BASE_IMAGE}
WORKDIR /srv
COPY server.py /srv/server.py
# The track is baked at build time: it is the image's identity, not
# something a running pod could be talked into changing.
ENV ARES_TRACK=${TRACK}
RUN useradd -u 10001 -M appuser && chown -R appuser /srv
USER 10001:10001
EXPOSE 8080
CMD ["python", "/srv/server.py"]
