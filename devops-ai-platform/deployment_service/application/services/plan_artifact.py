"""Canonical, symlink-safe handling of saved Terraform plan artifacts.

Phase 8.5-A corrective, Workstream E.

A saved Terraform plan is produced *inside* the sandbox, by untrusted
Terraform, into a workspace whose contents the untrusted workload can
fully control. Every host-side touch of that file is therefore a trust
boundary crossing of its own: the sandbox confines what Terraform can
*do*, but it does not stop Terraform from leaving a hostile **name**
behind -- most obviously a symlink such as::

    terraform.tfplan -> /etc/shadow
    terraform.tfplan -> ../../other-run/terraform.tfplan

If the host then hashes, reads, or applies that path naively, the
sandbox has been bypassed without ever being broken: the host reads a
file the workload could never have read itself.

Lexical checks are not sufficient, because the escape can be hidden in
any component of the path, including the workspace root itself. This
module is the single place allowed to turn a *claimed* plan path into a
*proven* one, and every host-side plan operation (hashing, reading,
applying, evidence, cleanup) must go through it.

The proof performed here is deliberately paranoid and ordered so that
nothing is read before confinement has been established:

1. the workspace root is resolved (symlinks followed) and must exist;
2. the candidate must be a direct child of that resolved root -- not a
   nested path, not ``..``, not absolute elsewhere;
3. the candidate must be the expected plan filename;
4. **no path component may be a symlink**, checked with ``lstat`` and
   without following links;
5. the candidate must be a regular file (not a directory, FIFO, socket
   or device);
6. the fully resolved candidate must still live directly beneath the
   resolved root -- this is what defeats a swapped root;
7. only then may the bytes be opened, and they are opened with
   ``O_NOFOLLOW`` so that a race between the check and the read still
   fails closed.

Anything that cannot be proven raises :class:`PlanArtifactError`, which
callers map to a BLOCKED outcome. There is no "best effort" path.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Tuple

#: The only filename a saved plan is ever allowed to have. Keeping this
#: fixed means a hostile workload cannot smuggle a different artifact
#: past the host by choosing a confusing name.
PLAN_FILENAME = "terraform.tfplan"

#: Saved plans are sensitive. They are read in bounded chunks and never
#: logged; this cap stops a hostile workload from exhausting control
#: plane memory by leaving a multi-gigabyte "plan" behind.
MAX_PLAN_BYTES = 64 * 1024 * 1024

_READ_CHUNK = 1024 * 1024


class PlanArtifactError(Exception):
    """A saved plan path could not be proven safe to touch."""

    def __init__(self, message: str, code: str = "PLAN_ARTIFACT_UNSAFE") -> None:
        super().__init__(message)
        self.code = code


def _resolved_root(workspace: str) -> Path:
    if not workspace or not str(workspace).strip():
        raise PlanArtifactError(
            "plan workspace must be a non-empty path",
            "PLAN_ARTIFACT_WORKSPACE_INVALID",
        )
    root = Path(workspace)
    if not root.is_absolute():
        raise PlanArtifactError(
            "plan workspace must be an absolute path",
            "PLAN_ARTIFACT_WORKSPACE_INVALID",
        )
    try:
        resolved = root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise PlanArtifactError(
            f"plan workspace does not resolve: {exc}",
            "PLAN_ARTIFACT_WORKSPACE_INVALID",
        ) from exc
    if not resolved.is_dir():
        raise PlanArtifactError(
            "plan workspace is not a directory",
            "PLAN_ARTIFACT_WORKSPACE_INVALID",
        )
    return resolved


def _reject_symlinked_components(root: Path, candidate: Path) -> None:
    """Fail if the candidate, or anything between it and ``root``, is a link.

    ``Path.resolve`` alone is not enough: it tells us where a path ends
    up, not whether a link was traversed. We want the stricter property
    that no link was involved at all, so a hostile workload cannot make
    the host follow a link it planted, even one that happens to resolve
    back inside the workspace.
    """
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:  # pragma: no cover - guarded by caller
        raise PlanArtifactError(
            "saved plan is not inside the approved workspace",
            "PLAN_ARTIFACT_OUTSIDE_WORKSPACE",
        ) from exc
    walked = root
    for part in relative.parts:
        walked = walked / part
        try:
            if os.path.islink(walked):
                raise PlanArtifactError(
                    f"saved plan path component is a symlink: {part!r}",
                    "PLAN_ARTIFACT_SYMLINK",
                )
        except OSError as exc:
            raise PlanArtifactError(
                f"saved plan path component cannot be inspected: {exc}",
                "PLAN_ARTIFACT_UNSAFE",
            ) from exc


def resolve_plan_artifact(workspace: str, plan_path: str) -> Path:
    """Return a proven-safe absolute path to the saved plan.

    Raises :class:`PlanArtifactError` if safety cannot be established.
    """
    root = _resolved_root(workspace)

    if not plan_path or not str(plan_path).strip():
        raise PlanArtifactError(
            "saved plan path must not be empty", "PLAN_ARTIFACT_MISSING"
        )

    raw = Path(plan_path)
    candidate = raw if raw.is_absolute() else root / raw

    # Reject traversal lexically first -- cheap, and it keeps obviously
    # hostile input from reaching the filesystem at all.
    if ".." in candidate.parts:
        raise PlanArtifactError(
            "saved plan path must not contain '..'",
            "PLAN_ARTIFACT_OUTSIDE_WORKSPACE",
        )
    if candidate.name != PLAN_FILENAME:
        raise PlanArtifactError(
            f"saved plan must be named {PLAN_FILENAME!r}",
            "PLAN_ARTIFACT_UNEXPECTED_NAME",
        )
    if candidate.parent != root:
        raise PlanArtifactError(
            "saved plan must be a direct child of the approved workspace",
            "PLAN_ARTIFACT_OUTSIDE_WORKSPACE",
        )

    _reject_symlinked_components(root, candidate)

    try:
        info = os.lstat(candidate)
    except FileNotFoundError as exc:
        raise PlanArtifactError(
            "saved plan artifact is missing", "PLAN_ARTIFACT_MISSING"
        ) from exc
    except OSError as exc:
        raise PlanArtifactError(
            f"saved plan artifact cannot be inspected: {exc}",
            "PLAN_ARTIFACT_UNSAFE",
        ) from exc

    import stat as _stat

    if _stat.S_ISLNK(info.st_mode):
        raise PlanArtifactError(
            "saved plan artifact is a symlink", "PLAN_ARTIFACT_SYMLINK"
        )
    if not _stat.S_ISREG(info.st_mode):
        raise PlanArtifactError(
            "saved plan artifact is not a regular file",
            "PLAN_ARTIFACT_NOT_REGULAR",
        )
    if info.st_size > MAX_PLAN_BYTES:
        raise PlanArtifactError(
            "saved plan artifact exceeds the permitted size",
            "PLAN_ARTIFACT_TOO_LARGE",
        )

    # Final confinement proof after all link checks: even if something
    # changed underneath us, the resolved location must still be the
    # exact approved child path.
    try:
        final = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise PlanArtifactError(
            f"saved plan artifact does not resolve: {exc}",
            "PLAN_ARTIFACT_UNSAFE",
        ) from exc
    if final.parent != root or final.name != PLAN_FILENAME:
        raise PlanArtifactError(
            "saved plan artifact resolves outside the approved workspace",
            "PLAN_ARTIFACT_OUTSIDE_WORKSPACE",
        )
    return final


def read_plan_bytes(workspace: str, plan_path: str) -> Tuple[Path, bytes]:
    """Read a proven-safe saved plan without ever following a symlink."""
    proven = resolve_plan_artifact(workspace, plan_path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(proven, flags)
    except OSError as exc:
        # ELOOP here means the file became a symlink between the check
        # and the open: the race loses, closed.
        raise PlanArtifactError(
            f"saved plan artifact could not be opened safely: {exc}",
            "PLAN_ARTIFACT_UNSAFE",
        ) from exc
    try:
        chunks = []
        total = 0
        while True:
            chunk = os.read(fd, _READ_CHUNK)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_PLAN_BYTES:
                raise PlanArtifactError(
                    "saved plan artifact exceeds the permitted size",
                    "PLAN_ARTIFACT_TOO_LARGE",
                )
            chunks.append(chunk)
    finally:
        os.close(fd)
    return proven, b"".join(chunks)


def hash_plan_artifact(workspace: str, plan_path: str) -> str:
    """SHA-256 over the exact saved plan bytes.

    The hash is the only representation of a plan that may ever be
    logged, persisted or returned over the API: plan contents can
    describe private infrastructure and are treated as sensitive.
    """
    _, data = read_plan_bytes(workspace, plan_path)
    return hashlib.sha256(data).hexdigest()
