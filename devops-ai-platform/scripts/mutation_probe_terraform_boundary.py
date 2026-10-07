#!/usr/bin/env python3
"""Prove the Terraform trust-boundary tests actually bite.

Phase 8.5-A corrective, §30.

A green security suite is worthless on its own: it may be green because
the controls work, or green because the tests never check them. The only
way to tell the two apart is to break each control deliberately and
confirm the suite notices.

This harness does that reproducibly and *without ever mutating the
working tree*: every mutation is applied to a throwaway copy of
``devops-ai-platform``, the relevant tests run against that copy, and the
copy is deleted. A mutation that leaves the suite green is reported as a
FAILED PROBE, because it means a real regression could ship unnoticed.

Usage::

    python scripts/mutation_probe_terraform_boundary.py          # all
    python scripts/mutation_probe_terraform_boundary.py --list
    python scripts/mutation_probe_terraform_boundary.py -k root

Exit code 0 only if every probe was caught.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Sequence

PLATFORM_ROOT = Path(__file__).resolve().parent.parent

SANDBOX = "deployment_service/application/services/terraform_sandbox.py"
RUNNER = "deployment_service/application/services/terraform_runner.py"
ADAPTER = "deployment_service/infrastructure/sandbox/container_terraform_sandbox.py"
ENGINE = "deployment_service/application/services/deployment_engine.py"
PLAN_ARTIFACT = "deployment_service/application/services/plan_artifact.py"

BOUNDARY_TESTS = "deployment_service/tests/test_terraform_trust_boundary.py"
APPROVAL_TESTS = "deployment_service/tests/test_terraform_approval_integrity.py"


class MutationNotApplied(RuntimeError):
    """The mutation's anchor text was not found -- the probe is stale."""


def replace(path: str, old: str, new: str, count: int = 1) -> Callable[[Path], None]:
    """Build a mutation that swaps exact text inside ``path``."""

    def apply(root: Path) -> None:
        target = root / path
        text = target.read_text(encoding="utf-8")
        found = text.count(old)
        if found != count:
            raise MutationNotApplied(
                f"{path}: expected {count} occurrence(s) of {old[:60]!r}, "
                f"found {found}. The implementation moved; update the probe "
                f"rather than deleting it."
            )
        target.write_text(text.replace(old, new, count), encoding="utf-8")

    return apply


@dataclass
class Probe:
    """One deliberate weakening, and the tests that must catch it."""

    name: str
    description: str
    mutate: Callable[[Path], None]
    tests: Sequence[str] = field(default_factory=lambda: [BOUNDARY_TESTS])
    #: True when this probe removes ONE layer of a deliberately redundant
    #: defence. Such a probe is EXPECTED to escape on its own, because a
    #: sibling layer still blocks the attack. Each of these must be
    #: covered by a combined probe that strips every layer at once --
    #: otherwise "defence in depth" is just an untested claim.
    redundant_layer: bool = False


PROBES: list[Probe] = [
    # ---- container isolation -------------------------------------
    Probe(
        "network-bridge",
        "allow bridged networking so Terraform can reach the network",
        replace(
            SANDBOX,
            'SANDBOX_ALLOWED_NETWORK_MODES = frozenset({"none"})',
            'SANDBOX_ALLOWED_NETWORK_MODES = frozenset({"none", "bridge"})',
        ),
    ),
    Probe(
        "writable-rootfs",
        "drop --read-only from the container runtime policy",
        replace(SANDBOX, '        "--read-only",\n', ""),
    ),
    Probe(
        "keep-capabilities",
        "stop dropping Linux capabilities",
        replace(SANDBOX, '        "--cap-drop",\n        "ALL",\n', ""),
    ),
    Probe(
        "allow-privilege-escalation",
        "remove no-new-privileges",
        replace(SANDBOX, '"no-new-privileges:true"', '"seccomp=unconfined"'),
    ),
    Probe(
        "root-sandbox",
        "permit a root Terraform container",
        replace(
            SANDBOX,
            '    if uid == 0:\n        raise TerraformSandboxPolicyViolation(\n'
            '            "terraform sandbox must run as a non-root user"\n        )',
            "    pass",
        ),
    ),
    Probe(
        "docker-socket",
        "mount the Docker socket into the untrusted Terraform container",
        replace(
            SANDBOX,
            '    cli_argv += ["-v", mounts[0], "-w", SANDBOX_WORKSPACE_MOUNT, spec.image]',
            '    cli_argv += ["-v", "/var/run/docker.sock:/var/run/docker.sock"]\n'
            '    cli_argv += ["-v", mounts[0], "-w", SANDBOX_WORKSPACE_MOUNT, spec.image]',
        ),
    ),
    Probe(
        "floating-image-tag",
        "accept a mutable :latest image instead of a digest",
        replace(
            SANDBOX,
            "    if not re.fullmatch(_IMAGE_DIGEST_PATTERN, image):",
            "    if False:",
        ),
    ),
    # ---- host execution ------------------------------------------
    Probe(
        "host-terraform-fallback",
        "fall back to host Terraform when the sandbox is unavailable",
        replace(
            RUNNER,
            "        except TerraformSandboxError as exc:",
            "        except TerraformSandboxError as exc:\n"
            "            import subprocess\n"
            "            host = subprocess.run(['terraform'], cwd=iac_dir,\n"
            "                                  capture_output=True, text=True)\n"
            '            return {"status": "PASS", "operation": operation.value,\n'
            '                    "stdout": "", "stderr": "", "executed": True}',
        ),
    ),
    Probe(
        "host-environment-inheritance",
        "let the sandbox inherit the control plane's environment",
        replace(
            SANDBOX,
            "    env = dict(SANDBOX_ENV_ALLOWLIST)",
            "    import os as _o\n"
            "    env = dict(SANDBOX_ENV_ALLOWLIST)\n"
            "    env.update(_o.environ)",
        ),
    ),
    # ---- approval integrity (the corrective's core) ---------------
    Probe(
        "replan-after-approval",
        "regenerate the plan at execution time instead of applying the "
        "approved one",
        replace(
            ENGINE,
            "            terraform_plan = dict(approved)",
            "            terraform_plan = self.terraform.run_plan(\n"
            "                tf_workspace, execution=True,\n"
            "                plan_output_path=str(Path(tf_workspace, PLAN_FILENAME)))\n"
            "            approved_plan_hash = terraform_plan.get('plan_file_hash', '')",
        ),
        tests=[APPROVAL_TESTS],
    ),
    Probe(
        "skip-approved-plan-verification",
        "apply without re-verifying the approved plan bytes",
        replace(
            ENGINE,
            "        if actual != approved_hash:",
            "        if False:",
        ),
        tests=[APPROVAL_TESTS],
    ),
    Probe(
        "unverified-apply",
        "allow apply with no approved hash to compare against",
        replace(
            RUNNER,
            "        if not expected_plan_file_hash:",
            "        if False:",
        ),
        tests=[BOUNDARY_TESTS, APPROVAL_TESTS],
    ),
    Probe(
        "ignore-credential-profile",
        "ignore a credential-profile change after approval",
        replace(
            ENGINE,
            "        if approved_profile and approved_profile != current_profile:",
            "        if False:",
        ),
        tests=[APPROVAL_TESTS],
    ),
    # ---- plan artifact safety ------------------------------------
    Probe(
        "follow-plan-symlink",
        "follow a symlink when reading the saved plan",
        replace(
            PLAN_ARTIFACT,
            "    if _stat.S_ISLNK(info.st_mode):",
            "    if False:",
        ),
        tests=[APPROVAL_TESTS],
        redundant_layer=True,
    ),
    Probe(
        "skip-component-symlink-check",
        "stop rejecting symlinked path components",
        replace(
            PLAN_ARTIFACT,
            "    _reject_symlinked_components(root, candidate)",
            "    pass",
        ),
        tests=[APPROVAL_TESTS],
        redundant_layer=True,
    ),
    Probe(
        "accept-irregular-plan",
        "accept a directory or FIFO as a saved plan",
        replace(
            PLAN_ARTIFACT,
            "    if not _stat.S_ISREG(info.st_mode):",
            "    if False:",
        ),
        tests=[APPROVAL_TESTS],
    ),
    Probe(
        "allow-plan-outside-workspace",
        "accept a plan path that is not inside the approved workspace",
        replace(
            PLAN_ARTIFACT,
            "    if candidate.parent != root:",
            "    if False:",
        ),
        tests=[APPROVAL_TESTS],
        redundant_layer=True,
    ),
    # ---- workspace ownership -------------------------------------
    Probe(
        "all-symlink-defences-removed",
        "strip every layer that stops a symlinked saved plan at once",
        lambda root: [
            replace(PLAN_ARTIFACT, "    if _stat.S_ISLNK(info.st_mode):", "    if False:")(root),
            replace(PLAN_ARTIFACT, "    _reject_symlinked_components(root, candidate)", "    pass")(root),
            replace(PLAN_ARTIFACT, "    if final.parent != root or final.name != PLAN_FILENAME:", "    if False:")(root),
            replace(PLAN_ARTIFACT, "flags = os.O_RDONLY | getattr(os, \"O_NOFOLLOW\", 0) | getattr(os, \"O_CLOEXEC\", 0)", "flags = os.O_RDONLY")(root),
        ],
        tests=[APPROVAL_TESTS],
    ),
    Probe(
        "all-confinement-defences-removed",
        "strip every layer that keeps the saved plan inside the workspace",
        lambda root: [
            replace(PLAN_ARTIFACT, "    if candidate.parent != root:", "    if False:")(root),
            replace(PLAN_ARTIFACT, "    if final.parent != root or final.name != PLAN_FILENAME:", "    if False:")(root),
            replace(PLAN_ARTIFACT, '    if ".." in candidate.parts:', "    if False:")(root),
        ],
        tests=[APPROVAL_TESTS],
    ),
    Probe(
        "world-writable-workspace",
        "make the approval workspace world-accessible instead of chowning it",
        replace(ENGINE, "os.chmod(workspace, 0o2770)", "os.chmod(workspace, 0o777)"),
        tests=[APPROVAL_TESTS],
    ),
]


def _copy_platform(destination: Path) -> Path:
    root = destination / "platform"
    shutil.copytree(
        PLATFORM_ROOT,
        root,
        ignore=shutil.ignore_patterns(
            "__pycache__", "*.pyc", ".pytest_cache", "node_modules", ".git"
        ),
    )
    return root


def run_probe(probe: Probe, verbose: bool) -> tuple[bool, str]:
    with tempfile.TemporaryDirectory(prefix="tf-mutation-") as tmp:
        root = _copy_platform(Path(tmp))
        try:
            probe.mutate(root)
        except MutationNotApplied as exc:
            return False, f"PROBE STALE: {exc}"
        completed = subprocess.run(
            [sys.executable, "-m", "pytest", *probe.tests, "-q",
             "--no-header", "-p", "no:cacheprovider"],
            cwd=root,
            env={"PYTHONPATH": str(root), "PATH": __import__("os").environ["PATH"],
                 "HOME": tmp},
            capture_output=True,
            text=True,
        )
        tail = (completed.stdout or completed.stderr).strip().splitlines()
        summary = tail[-1] if tail else "(no output)"
        if verbose:
            print("\n".join(tail[-12:]))
        # The suite MUST fail. Exit code 0 means the weakening went
        # unnoticed, which is the thing this harness exists to catch.
        return completed.returncode != 0, summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="list probes")
    parser.add_argument("-k", dest="filter", default="", help="substring filter")
    parser.add_argument("-v", dest="verbose", action="store_true")
    args = parser.parse_args()

    selected = [p for p in PROBES if args.filter in p.name]
    if args.list:
        for probe in selected:
            print(f"{probe.name:34s} {probe.description}")
        return 0
    if not selected:
        print(f"no probes match {args.filter!r}")
        return 1

    print(f"Running {len(selected)} bypass probes against an isolated copy.\n")
    escaped = []
    redundant = []
    for probe in selected:
        caught, summary = run_probe(probe, args.verbose)
        if caught:
            label = "CAUGHT"
        elif probe.redundant_layer:
            # Expected: a sibling layer blocked the attack on its own.
            label = "LAYERED"
            redundant.append(probe)
        else:
            label = "ESCAPED"
            escaped.append(probe)
        print(f"  [{label:7s}] {probe.name:34s} {summary}")

    print()
    if redundant:
        print(f"{len(redundant)} probe(s) were absorbed by a sibling defence "
              f"(expected; the combined probes prove the stack as a whole):")
        for probe in redundant:
            print(f"  - {probe.name}")
        print()
    if escaped:
        print(f"{len(escaped)} MUTATION(S) ESCAPED -- these weakenings are not "
              f"detected by the test suite:")
        for probe in escaped:
            print(f"  - {probe.name}: {probe.description}")
        return 1
    print(f"All {len(selected)} bypass probes were caught by the test suite.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
