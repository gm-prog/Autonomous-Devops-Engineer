import logging
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from domain.entities.hotfix_proposal import HotfixProposal
from application.services.remediation_workspace_service import RemediationWorkspace

logger = logging.getLogger("RemediationPatchExecutor")

_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
_MAX_PATCH_BYTES = 256 * 1024
_GIT_TIMEOUT_SECONDS = 60.0


class RemediationPatchError(RuntimeError):
    """Base error for deterministic patch execution."""


class PatchSourceMismatchError(RemediationPatchError):
    """The proposal was not generated for this exact workspace revision."""


class PatchWorkspaceDirtyError(RemediationPatchError):
    """The workspace contained changes before or outside the expected patch."""


class PatchApplicationRejectedError(RemediationPatchError):
    """Git rejected the patch during check or application."""


class PatchPostconditionError(RemediationPatchError):
    """The applied workspace did not match the expected single-file change."""


@dataclass(frozen=True)
class RemediationPatchExecutionResult:
    repository_slug: str
    source_sha: str
    target_filepath: str
    branch_name: str
    changed_paths: tuple[str, ...]


class RemediationPatchExecutor:
    """Applies one already-verified patch inside one immutable, isolated workspace."""

    def __init__(self, git_timeout_seconds: float = _GIT_TIMEOUT_SECONDS):
        if git_timeout_seconds <= 0:
            raise ValueError("git_timeout_seconds must be greater than zero")
        self.git_timeout_seconds = git_timeout_seconds

    def apply(
        self,
        workspace: RemediationWorkspace,
        proposal: HotfixProposal,
    ) -> RemediationPatchExecutionResult:
        self._validate_source_binding(workspace, proposal)
        target = self._validate_target(proposal.target_filepath)
        patch = proposal.diff_patch_payload.encode("utf-8")

        if len(patch) > _MAX_PATCH_BYTES:
            raise PatchApplicationRejectedError(
                f"patch exceeds {_MAX_PATCH_BYTES} bytes"
            )

        workspace_path = Path(workspace.path).resolve()
        if not workspace_path.is_dir():
            raise PatchApplicationRejectedError("remediation workspace does not exist")

        patch_file = None
        patch_temp_dir = None
        try:
            self._assert_clean_workspace(workspace_path)

            tracked = self._run_git(
                ["git", "ls-files", "--error-unmatch", "--", target],
                cwd=workspace_path,
            )
            if tracked.stdout.strip() != target:
                raise PatchApplicationRejectedError(
                    "remediation target is not a tracked file in the pinned workspace"
                )

            patch_temp_dir = Path(tempfile.mkdtemp(prefix="devops-remediation-patch-"))
            with tempfile.NamedTemporaryFile(
                mode="wb",
                prefix="patch-",
                suffix=".diff",
                dir=patch_temp_dir,
                delete=False,
            ) as handle:
                handle.write(patch)
                patch_file = Path(handle.name).resolve()

            self._run_git(
                ["git", "apply", "--check", "--whitespace=error-all", str(patch_file)],
                cwd=workspace_path,
            )
            self._run_git(
                ["git", "apply", "--whitespace=error-all", str(patch_file)],
                cwd=workspace_path,
            )

            changed_paths = self._verify_postconditions(workspace_path, target)
            return RemediationPatchExecutionResult(
                repository_slug=workspace.repository_slug,
                source_sha=workspace.source_sha,
                target_filepath=target,
                branch_name=workspace.branch_name,
                changed_paths=changed_paths,
            )
        except subprocess.CalledProcessError as exc:
            raise PatchApplicationRejectedError(
                "Git rejected the remediation patch"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise PatchApplicationRejectedError(
                "Git patch execution exceeded the bounded timeout"
            ) from exc
        finally:
            if patch_file is not None:
                try:
                    patch_file.unlink(missing_ok=True)
                except OSError:
                    logger.warning("Could not remove temporary remediation patch file")
            if patch_temp_dir is not None:
                try:
                    patch_temp_dir.rmdir()
                except OSError:
                    logger.warning("Could not remove temporary remediation patch directory")

    @staticmethod
    def _validate_source_binding(
        workspace: RemediationWorkspace,
        proposal: HotfixProposal,
    ) -> None:
        if not proposal.is_verified:
            raise PatchSourceMismatchError(
                "proposal must pass deterministic patch verification before execution"
            )

        workspace_sha = workspace.source_sha.strip().lower()
        proposal_sha = (proposal.source_sha or "").strip().lower()
        if not _SHA_PATTERN.fullmatch(workspace_sha):
            raise PatchSourceMismatchError("workspace source SHA is invalid")
        if not _SHA_PATTERN.fullmatch(proposal_sha):
            raise PatchSourceMismatchError("proposal source SHA is invalid")
        if workspace_sha != proposal_sha:
            raise PatchSourceMismatchError(
                "proposal source SHA does not match workspace source SHA"
            )

    @staticmethod
    def _validate_target(target_filepath: str) -> str:
        target = target_filepath.replace("\\", "/").strip()
        if not target or target.startswith("/"):
            raise PatchApplicationRejectedError("target filepath is unsafe")
        if any(segment in {"", ".", ".."} for segment in target.split("/")):
            raise PatchApplicationRejectedError("target filepath contains unsafe segments")
        return target

    def _assert_clean_workspace(self, workspace_path: Path) -> None:
        result = self._run_git(
            ["git", "status", "--porcelain=v1", "--untracked-files=all"],
            cwd=workspace_path,
        )
        if result.stdout.strip():
            raise PatchWorkspaceDirtyError(
                "remediation workspace must be clean before patch execution"
            )

    def _verify_postconditions(
        self,
        workspace_path: Path,
        target: str,
    ) -> tuple[str, ...]:
        status = self._run_git(
            ["git", "status", "--porcelain=v1", "--untracked-files=all"],
            cwd=workspace_path,
        ).stdout.splitlines()
        if len(status) != 1:
            raise PatchPostconditionError(
                "remediation patch must produce exactly one workspace change"
            )

        entry = status[0]
        if len(entry) < 4 or entry[:2] != " M" or entry[3:] != target:
            raise PatchPostconditionError(
                "remediation patch changed an unexpected path or file state"
            )

        changed_paths = tuple(
            line.strip()
            for line in self._run_git(
                ["git", "diff", "--name-only", "--", target],
                cwd=workspace_path,
            ).stdout.splitlines()
            if line.strip()
        )
        if changed_paths != (target,):
            raise PatchPostconditionError(
                "post-apply Git diff does not contain exactly the target file"
            )

        return changed_paths

    def _run_git(
        self,
        args: list[str],
        cwd: Path,
    ) -> subprocess.CompletedProcess[str]:
        if args[:1] != ["git"]:
            raise PatchApplicationRejectedError(
                "patch executor accepts only fixed Git commands"
            )

        env = {
            key: value
            for key, value in os.environ.items()
            if key not in {"GIT_SSH_COMMAND", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM"}
        }
        env["GIT_TERMINAL_PROMPT"] = "0"

        return subprocess.run(
            args,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            check=True,
            shell=False,
            env=env,
            timeout=self.git_timeout_seconds,
        )
