# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
# check=skip=InvalidDefaultArgInFrom;error=true

# Phase 8.4.2 — remediation validation sandbox image.
# The sandbox runs untrusted repository commands, so it carries NOTHING
# but the digest-pinned base and a non-root user; the runtime boundary
# (--pull never, --network none, --read-only, --cap-drop ALL,
# --security-opt no-new-privileges, single :ro workspace bind) is
# enforced by validation_sandbox.py, not by this file.
#
# Phase 8.4.2-E1: previously generated inline by the golden-path
# workflow with a `printf` into /tmp, which (a) used the Compose-only
# required-value form in a FROM instruction — syntax the Dockerfile
# parser does not accept — and (b) could not be covered by the CI
# BuildKit contract gate. It is a committed file so the gate checks
# the exact bytes the workflow builds.
#
# Immutable build input: BASE_IMAGE must be a <name>@sha256:<64hex>
# reference from the committed pin file. No default, no fallback —
# omitting the build argument leaves the base name blank and BuildKit
# refuses the build.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
USER nobody
