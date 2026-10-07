#!/usr/bin/env python3
"""Static proof that nothing can execute Terraform on the host.

Phase 8.5-A corrective, §28.

The original guard only checked that ``terraform_runner.py`` did not
import ``subprocess``. That is too narrow in one direction and too blunt
in the other: the real boundary spans four modules, and one of them
(the container adapter) *must* use ``subprocess`` -- to launch the
container runtime, which is the whole point.

So this guard works on the AST and distinguishes by **what is being
executed**, not by which module is importing what:

* launching ``docker``/``podman`` from the dedicated trusted adapter is
  allowed, because that is the mechanism that enforces the boundary;
* launching ``terraform`` from anywhere is forbidden;
* ``os.system``, ``shell=True``, ``bash -c`` and ``sh -c`` are forbidden
  everywhere on the surface, because each of them re-introduces a shell
  that untrusted content could influence;
* any process-spawning API at all is forbidden in the three modules that
  have no business spawning anything.

Run it from ``devops-ai-platform``. Exit code 0 means clean; 1 means a
violation; 2 means the guard itself could not run, which is also a
failure (a guard that silently does nothing is worse than none).
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

PLATFORM_ROOT = Path(__file__).resolve().parent.parent

#: The module that is ALLOWED to spawn a container runtime. It is the
#: trusted host-side adapter: its entire job is to start the sandbox.
TRUSTED_ADAPTER = (
    "deployment_service/infrastructure/sandbox/container_terraform_sandbox.py"
)

#: Modules that must never spawn a process of any kind.
NO_EXECUTION_MODULES = (
    "deployment_service/application/services/terraform_runner.py",
    "deployment_service/application/services/terraform_sandbox.py",
    "deployment_service/application/services/plan_artifact.py",
    "deployment_service/application/services/deployment_engine.py",
)

#: Only these may ever be argv[0] of a spawned process, and only in the
#: trusted adapter.
ALLOWED_EXECUTABLES = frozenset({"docker", "podman"})

#: Process-spawning APIs we refuse to see outside the adapter.
SPAWN_CALLS = frozenset(
    {
        "subprocess.run", "subprocess.Popen", "subprocess.call",
        "subprocess.check_call", "subprocess.check_output",
        "subprocess.getoutput", "subprocess.getstatusoutput",
        "os.system", "os.popen", "os.execv", "os.execve", "os.execvp",
        "os.execvpe", "os.spawnv", "os.spawnve", "os.spawnl", "os.posix_spawn",
        "pty.spawn", "commands.getoutput",
    }
)

FORBIDDEN_TOKENS = ("bash", "sh", "terraform", "/bin/sh", "/bin/bash", "-c")


def dotted(node: ast.AST) -> str:
    """Render ``a.b.c`` from an attribute/name chain."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def literal_strings(node: ast.AST) -> list[str]:
    """Collect string constants appearing anywhere inside a node."""
    found = []
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            found.append(child.value)
    return found


class Auditor(ast.NodeVisitor):
    def __init__(self, relpath: str) -> None:
        self.relpath = relpath
        self.is_adapter = relpath == TRUSTED_ADAPTER
        self.violations: list[str] = []

    def fail(self, node: ast.AST, message: str) -> None:
        self.violations.append(f"{self.relpath}:{getattr(node, 'lineno', 0)}: {message}")

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        name = dotted(node.func)

        # shell=True is never acceptable anywhere on this surface.
        for keyword in node.keywords:
            if keyword.arg == "shell":
                is_true = isinstance(keyword.value, ast.Constant) and (
                    keyword.value.value is True
                )
                if is_true or not isinstance(keyword.value, ast.Constant):
                    self.fail(node, "shell=True (or a non-literal shell=) is "
                                    "forbidden on the Terraform boundary")

        if name in SPAWN_CALLS:
            if not self.is_adapter:
                self.fail(node, f"{name}() may not spawn processes here; only "
                                f"{TRUSTED_ADAPTER} may launch the sandbox")
            else:
                self._audit_adapter_spawn(node, name)

        self.generic_visit(node)

    def _audit_adapter_spawn(self, node: ast.Call, name: str) -> None:
        """Inside the adapter: the spawn must be a container runtime."""
        if name in {"os.system", "os.popen"}:
            self.fail(node, f"{name}() invokes a shell and is forbidden even "
                            "in the trusted adapter")
            return
        if not node.args:
            return
        argv = node.args[0]
        strings = literal_strings(argv)

        # The first literal we can see must be an approved runtime, and
        # none of the literals may smuggle in a shell or terraform.
        for value in strings:
            lowered = value.strip().lower()
            if lowered in {"terraform", "/usr/local/bin/terraform"}:
                self.fail(node, "the adapter must launch the container "
                                "runtime, never terraform directly")
            if lowered in {"bash", "sh", "/bin/sh", "/bin/bash", "zsh"}:
                self.fail(node, f"shell executable {value!r} must not be spawned")
        if strings and strings[0].strip().lower() not in ALLOWED_EXECUTABLES:
            # Tolerate indirection (a variable holding the runtime name)
            # only when no literal executable is present at all.
            if isinstance(argv, (ast.List, ast.Tuple)) and argv.elts:
                first = argv.elts[0]
                if isinstance(first, ast.Constant):
                    self.fail(node, f"spawned executable {first.value!r} is not "
                                    f"an approved container runtime "
                                    f"{sorted(ALLOWED_EXECUTABLES)}")


def audit(relpath: str) -> list[str]:
    path = PLATFORM_ROOT / relpath
    if not path.is_file():
        return [f"{relpath}: MISSING -- the guard cannot prove anything"]
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    auditor = Auditor(relpath)
    auditor.visit(tree)

    # Belt and braces: the non-adapter modules must not even import a
    # process API, so a future edit cannot quietly start using one.
    if relpath != TRUSTED_ADAPTER:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] in {"subprocess", "pty"}:
                        auditor.fail(node, f"import {alias.name} is forbidden here")
            elif isinstance(node, ast.ImportFrom):
                if (node.module or "").split(".")[0] in {"subprocess", "pty"}:
                    auditor.fail(node, f"from {node.module} import ... is forbidden here")
    return auditor.violations


def main() -> int:
    targets = [TRUSTED_ADAPTER, *NO_EXECUTION_MODULES]
    violations: list[str] = []
    for relpath in targets:
        found = audit(relpath)
        status = "CLEAN" if not found else f"{len(found)} VIOLATION(S)"
        print(f"  [{status:16s}] {relpath}")
        violations.extend(found)

    print()
    if violations:
        print("HOST TERRAFORM EXECUTION GUARD FAILED:")
        for item in violations:
            print(f"  {item}")
        return 1
    print(f"No host Terraform execution path exists across "
          f"{len(targets)} audited modules.")
    print(f"Only {TRUSTED_ADAPTER} may spawn a process, and only a "
          f"container runtime {sorted(ALLOWED_EXECUTABLES)}.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SyntaxError as exc:  # a file that will not parse proves nothing
        print(f"GUARD COULD NOT RUN: {exc}")
        raise SystemExit(2) from exc
