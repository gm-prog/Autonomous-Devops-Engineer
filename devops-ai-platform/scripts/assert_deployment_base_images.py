#!/usr/bin/env python3
"""Assert the deployment runtime chain uses only the approved base image.

Phase 8.8A Correction-1 (F6): the canonical deployment Dockerfile used a
floating ``python:3.11-slim`` tag. The correction pins the base to the
exact digest the repository already approves (``e2e/pinned-images.txt``,
key ``E2E_PYTHON_BASE_IMAGE``) and this guard makes the pin
STRUCTURAL, not a convention:

* every production service Dockerfile (deployment API+worker share
  ``deployment_service/Dockerfile``; the gateway and agent use the same
  approved definition) must reference a ``<name>@sha256:<64hex>`` base;
* the digest must EXACTLY match the approved pin — a different (even
  valid) digest is a violation: the approved image is the tested image;
* truncated digests, floating tags, and tag-only references are refused;
* ARG-based E2E variants must take ``BASE_IMAGE`` from the pinned file
  through the compose build args (``${E2E_PYTHON_BASE_IMAGE}``), so a
  build cannot substitute a floating base silently.

Exit code 0 only when every checked reference is exactly the approved
pin; the digest is printed for CI evidence (digest parity).

Usage::

    python scripts/assert_deployment_base_images.py [--list]
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

PLATFORM_ROOT = Path(__file__).resolve().parent.parent

#: (dockerfile,) ARG-based E2E variants: the base must arrive from the
#: approved pin (E2E_PYTHON_BASE_IMAGE, wired by the CI workflow / E2E
#: drivers), never from a floating default.
ARG_BASE_VARIANTS = (
    "deployment_service/Dockerfile.e2e",
    "deployment_service/Dockerfile.terraform-sandbox",
)

#: The workflow that wires the pin into the ARG-based builds.
WORKFLOW = ".github/workflows/ci.yml"

#: Production service images: the same approved, digest-pinned base.
PINNED_PRODUCTION = (
    "deployment_service/Dockerfile",
    "api-gateway/Dockerfile",
    "agent-service/Dockerfile",
)

_FULL_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_TRUNCATED_DIGEST = re.compile(r"sha256:[0-9a-f]{1,63}([^0-9a-f]|$)")
_FROM = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(.+?)\s*$", re.IGNORECASE)


def approved_digest() -> str:
    """The single source of truth: e2e/pinned-images.txt."""
    pin = PLATFORM_ROOT / "e2e" / "pinned-images.txt"
    for line in pin.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 3 and parts[2] == "E2E_PYTHON_BASE_IMAGE":
            digest = parts[1]
            if not _FULL_DIGEST.match(digest):
                raise SystemExit(
                    f"FAIL: the approved pin itself is not a full digest: "
                    f"{digest!r} in {pin}"
                )
            return digest
    raise SystemExit(f"FAIL: E2E_PYTHON_BASE_IMAGE pin not found in {pin}")


def _check_pinned(dockerfile: Path, digest: str) -> list[str]:
    problems = []
    for lineno, line in enumerate(dockerfile.read_text(encoding="utf-8").splitlines(), 1):
        if line.strip().startswith("#"):
            continue
        match = _FROM.match(line)
        if not match:
            continue
        reference = match.group(1).strip()
        if reference.startswith("$"):
            problems.append(
                f"{dockerfile}:{lineno}: FROM {reference!r} — production "
                f"images may not use build-argument bases"
            )
            continue
        if "@" not in reference:
            problems.append(
                f"{dockerfile}:{lineno}: floating base {reference!r} — "
                f"tag-only references drift; use <name>@{digest}"
            )
            continue
        name, _, ref_digest = reference.rpartition("@")
        if not _FULL_DIGEST.match(ref_digest):
            problems.append(
                f"{dockerfile}:{lineno}: digest in {reference!r} is "
                f"truncated or malformed (need sha256:<64 hex>)"
            )
            continue
        if ref_digest != digest:
            problems.append(
                f"{dockerfile}:{lineno}: base {name!r} pinned to "
                f"{ref_digest}, but the approved pin is {digest} — "
                f"a different base is a different (untested) image"
            )
    return problems


def _check_arg_variant(dockerfile: Path, workflow: Path) -> list[str]:
    problems = []
    text = dockerfile.read_text(encoding="utf-8")
    if not re.search(r"^\s*ARG\s+BASE_IMAGE\s*$", text, re.MULTILINE):
        problems.append(
            f"{dockerfile}: must declare `ARG BASE_IMAGE` so the base is "
            f"supplied by the approved pin, never hard-coded to a tag"
        )
    # no floating tag may sneak in as an ARG default
    for lineno, line in enumerate(text.splitlines(), 1):
        match = re.match(r"^\s*ARG\s+BASE_IMAGE=(\S+)", line)
        if match and "@" not in match.group(1):
            problems.append(
                f"{dockerfile}:{lineno}: ARG BASE_IMAGE default "
                f"{match.group(1)!r} is a floating reference"
            )
    # the build wiring must take the base from the approved pin
    if workflow.exists() and "E2E_PYTHON_BASE_IMAGE" not in workflow.read_text(encoding="utf-8"):
        problems.append(
            f"{workflow}: must wire BASE_IMAGE to E2E_PYTHON_BASE_IMAGE "
            f"(the committed approved pin)"
        )
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true",
                        help="list the checked references and exit 0")
    args = parser.parse_args(argv)

    digest = approved_digest()
    print(f"approved base digest: {digest}")

    problems: list[str] = []
    checked = 0
    for rel in PINNED_PRODUCTION:
        dockerfile = PLATFORM_ROOT / rel
        if not dockerfile.exists():
            problems.append(f"missing Dockerfile: {rel}")
            continue
        checked += 1
        problems.extend(_check_pinned(dockerfile, digest))

    workflow = PLATFORM_ROOT.parent / WORKFLOW
    for rel in ARG_BASE_VARIANTS:
        dockerfile = PLATFORM_ROOT / rel
        if not dockerfile.exists():
            problems.append(f"missing Dockerfile: {rel}")
            continue
        checked += 1
        problems.extend(_check_arg_variant(dockerfile, workflow))

    if args.list:
        print(f"checked {checked} Dockerfile definitions")
        for rel in PINNED_PRODUCTION:
            print(f"  pinned:      {rel}")
        for rel in ARG_BASE_VARIANTS:
            print(f"  arg-wired:   {rel}")
        return 0

    if problems:
        for problem in problems:
            print(f"FAIL: {problem}")
        return 1
    print(
        f"OK: all {checked} checked deployment-runtime Dockerfile "
        f"definitions use the approved pin {digest}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
