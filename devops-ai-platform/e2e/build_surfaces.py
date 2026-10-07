"""Authoritative inventory of the Phase 8.4.2 E2E build surfaces (§10).

One list, consumed by every layer, so the Compose override, the CI
BuildKit contract gate and the regression tests can never drift apart:

``E2E_BUILD_SURFACES``
    compose service -> E2E-only Dockerfile (as written in
    ``docker-compose.e2e.yml``). Two incident services intentionally
    share one Dockerfile.
``E2E_DOCKERFILES``
    every DISTINCT Dockerfile the E2E stack builds, with the build
    context it is built from — including the two surfaces that are not
    compose services (the fixture workload and the remediation
    validation sandbox).

Phase 8.4.2-E1 contract for each of those files:

* ``ARG BASE_IMAGE`` + ``FROM ${BASE_IMAGE}`` — the only Dockerfile
  variable form Docker actually supports here. ``${BASE_IMAGE:?…}`` is
  Compose interpolation syntax and is rejected by the Dockerfile parser.
* no default, no fallback, no second base-image source: omitting
  ``--build-arg BASE_IMAGE`` makes the base name blank and the build
  fails closed.
* the required-value check stays in Compose
  (``${E2E_PYTHON_BASE_IMAGE:?…}``), where ``:?`` is valid.

``--plan`` prints ``<dockerfile>\t<context>`` (repository-root relative)
for the CI gate, so the gate iterates this list rather than its own copy.
"""

from __future__ import annotations

import os
import re
import sys
from typing import Dict, List, Sequence, Tuple

#: Repository-root relative directory holding the platform sources.
PLATFORM_DIR = "devops-ai-platform"

#: §6.2 — compose services the golden-path `compose build` actually
#: builds, mapped to the E2E Dockerfile that owns each build surface
#: (paths exactly as they appear in docker-compose.e2e.yml).
E2E_BUILD_SURFACES: Dict[str, str] = {
    "api-gateway": "./api_gateway/Dockerfile.e2e",
    "repo-service": "./repo_service/Dockerfile.e2e",
    "agent-service": "./agent_service/Dockerfile.e2e",
    "deployment-service": "./deployment_service/Dockerfile.e2e",
    "monitoring-service": "./monitoring_service/Dockerfile.e2e",
    "incident-service": "./incident_service/Dockerfile.e2e",
    "incident-event-worker": "./incident_service/Dockerfile.e2e",
}

#: The compose build context shared by every service build surface.
COMPOSE_BUILD_CONTEXT = "./devops-ai-platform"

#: Distinct Dockerfile -> build context, repository-root relative.
#: The compose services collapse to six files (incident-service and
#: incident-event-worker share one); the workload and sandbox images are
#: built directly by the workflow, not by compose.
E2E_DOCKERFILES: Tuple[Tuple[str, str], ...] = (
    (f"{PLATFORM_DIR}/api_gateway/Dockerfile.e2e", PLATFORM_DIR),
    (f"{PLATFORM_DIR}/repo_service/Dockerfile.e2e", PLATFORM_DIR),
    (f"{PLATFORM_DIR}/agent_service/Dockerfile.e2e", PLATFORM_DIR),
    (f"{PLATFORM_DIR}/deployment_service/Dockerfile.e2e", PLATFORM_DIR),
    (f"{PLATFORM_DIR}/monitoring_service/Dockerfile.e2e", PLATFORM_DIR),
    (f"{PLATFORM_DIR}/incident_service/Dockerfile.e2e", PLATFORM_DIR),
    (f"{PLATFORM_DIR}/e2e/workload/Dockerfile", f"{PLATFORM_DIR}/e2e/workload"),
    (f"{PLATFORM_DIR}/e2e/sandbox/Dockerfile", f"{PLATFORM_DIR}/e2e/sandbox"),
)

#: Build argument every E2E surface consumes, and the committed pin key
#: whose digest supplies it.
BASE_IMAGE_ARG = "BASE_IMAGE"
BASE_IMAGE_PIN_KEY = "E2E_PYTHON_BASE_IMAGE"

#: Pinned Dockerfile frontend. A floating ``docker/dockerfile:1`` would
#: reintroduce exactly the mutable-input class this phase closed, and
#: would let a newly released check rule break the build later; the
#: digest below is the frontend index digest read from the registry API
#: (docker/dockerfile tags `1` and `latest`, 2026-09-30 push).
SYNTAX_DIRECTIVE = (
    "# syntax=docker/dockerfile:1@sha256:"
    "4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e"
)

#: ``InvalidDefaultArgInFrom`` asserts that a build must succeed with no
#: ``--build-arg``. That is the opposite of this contract: the E2E images
#: MUST refuse to build unless the caller supplies the committed digest.
#: The rule is skipped by name (never ``skip=all``) and every other check
#: is promoted to an error.
CHECK_DIRECTIVE = "# check=skip=InvalidDefaultArgInFrom;error=true"

#: The exact two-line header every E2E Dockerfile must start with.
REQUIRED_HEADER = (SYNTAX_DIRECTIVE, CHECK_DIRECTIVE)

#: The only base-image expression allowed in an E2E Dockerfile.
REQUIRED_FROM = "FROM ${BASE_IMAGE}"

#: Dockerfile variable forms that must never appear around BASE_IMAGE:
#: ``:?``/``?`` are Compose-only (unsupported by the Dockerfile parser),
#: the rest would silently substitute a value the pin file never vouched
#: for.
FORBIDDEN_BASE_IMAGE_FORMS = (
    "${BASE_IMAGE:?",
    "${BASE_IMAGE?",
    "${BASE_IMAGE:-",
    "${BASE_IMAGE-",
    "${BASE_IMAGE:+",
    "${BASE_IMAGE+",
    "ARG BASE_IMAGE=",
)


def dockerfiles() -> Tuple[str, ...]:
    """Distinct E2E Dockerfile paths (repository-root relative)."""
    return tuple(path for path, _ in E2E_DOCKERFILES)


def _instruction_lines(text: str) -> List[str]:
    """Dockerfile lines with comments and blanks removed."""
    return [
        line
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def validate_dockerfile_text(text: str) -> List[str]:
    """Static E2E Dockerfile contract — returns a list of violations.

    Shared by the CI BuildKit gate (which runs it before handing the
    file to real BuildKit) and by the regression tests, so there is one
    definition of "acceptable" rather than several. It is deliberately
    *not* a substitute for the real parser: BuildKit proves the syntax,
    this proves the repository's intent.
    """
    problems: List[str] = []
    lines = text.splitlines()

    if lines[:2] != list(REQUIRED_HEADER):
        problems.append(
            "the first two lines must be the pinned syntax directive and "
            "the check directive (parser directives must precede comments)"
        )

    for form in FORBIDDEN_BASE_IMAGE_FORMS:
        if form in text:
            kind = (
                "Compose-only required-value interpolation"
                if form.endswith("?")
                else "a default/fallback value"
            )
            problems.append(f"{form!r} is {kind} and must not appear")

    instructions = _instruction_lines(text)
    froms = [line for line in instructions if line.upper().startswith("FROM ")]
    if froms != [REQUIRED_FROM]:
        problems.append(f"expected exactly one {REQUIRED_FROM!r}, found {froms!r}")

    declaration = f"ARG {BASE_IMAGE_ARG}"
    if declaration not in instructions:
        problems.append(f"missing a default-free {declaration!r} declaration")
    elif REQUIRED_FROM in instructions and (
        instructions.index(declaration) + 1 != instructions.index(REQUIRED_FROM)
    ):
        problems.append(
            f"{declaration!r} must be the instruction immediately before the "
            "FROM it feeds"
        )

    body = "\n".join(instructions)
    if re.search(r"python[:@]", body):
        problems.append(
            "a second python base source would compete with the committed pin"
        )
    return problems


def validate_all(root: str = ".") -> Dict[str, List[str]]:
    """Validate every committed E2E Dockerfile; path -> violations."""
    report: Dict[str, List[str]] = {}
    for path in dockerfiles():
        full = os.path.join(root, path)
        try:
            with open(full, encoding="utf-8") as handle:
                text = handle.read()
        except OSError as exc:
            report[path] = [f"unreadable: {exc}"]
            continue
        problems = validate_dockerfile_text(text)
        if problems:
            report[path] = problems
    return report


def plan_lines() -> Tuple[str, ...]:
    """``<dockerfile>\\t<context>`` lines for the CI BuildKit gate."""
    return tuple(f"{path}\t{context}" for path, context in E2E_DOCKERFILES)


def main(argv: Sequence[str] | None = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    if args == ["--plan"]:
        print("\n".join(plan_lines()))
        return 0
    if args == ["--dockerfiles"]:
        print("\n".join(dockerfiles()))
        return 0
    if args and args[0] == "--validate":
        root = args[1] if len(args) == 2 else "."
        report = validate_all(root)
        for path, problems in sorted(report.items()):
            for problem in problems:
                print(f"::error file={path}::{problem}", file=sys.stderr)
        if report:
            return 1
        print(f"static contract OK for {len(dockerfiles())} E2E Dockerfiles")
        return 0
    print(
        "usage: python -m e2e.build_surfaces --plan|--dockerfiles|--validate [root]",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    sys.exit(main())
