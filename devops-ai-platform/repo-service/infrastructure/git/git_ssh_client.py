import logging
import os
import subprocess
from typing import Any, Dict, List, Optional

from ...domain.exceptions import InvalidGitRepositoryException

logger = logging.getLogger("GitSSHClient")

MAX_COMMITS = 5
MAX_CHANGED_FILES_PER_COMMIT = 25
MAX_PATH_LENGTH = 256
MAX_SUBJECT_LENGTH = 512
MAX_AUTHOR_LENGTH = 128


class GitSSHClient:
    """Provides credential-based clones and bounded Git metadata inspection."""

    def __init__(self, private_key_path: Optional[str] = None):
        self.pkey = private_key_path or os.getenv("DEVOPS_SSH_KEY_PATH", "")

    def clone_repository(self, repo_url: str, dest_dir: str) -> bool:
        logger.info(
            "Cloning codebase from private host: %s into local cache namespace %s",
            repo_url,
            dest_dir,
        )

        env = os.environ.copy()
        if self.pkey:
            if not os.path.exists(self.pkey):
                logger.warning(
                    "Configured SSH key path %s does not exist. Proceeding with fallback keys.",
                    self.pkey,
                )
            env["GIT_SSH_COMMAND"] = (
                f"ssh -i {self.pkey} -o StrictHostKeyChecking=no "
                "-o UserKnownHostsFile=/dev/null"
            )
        else:
            env["GIT_SSH_COMMAND"] = (
                "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
            )

        try:
            subprocess.run(
                ["git", "clone", repo_url, dest_dir],
                capture_output=True,
                text=True,
                check=True,
                env=env,
                timeout=120,
            )
            logger.info("Clone successfully processed and cataloged.")
            return True
        except subprocess.TimeoutExpired as exc:
            logger.error("Git clone operation timed out after 120 seconds: %s", exc)
            raise InvalidGitRepositoryException(
                "Repository clone exceeded timeout limits (120s)"
            ) from exc
        except subprocess.CalledProcessError as exc:
            logger.error(
                "Git execution failed with code %s: %s",
                exc.returncode,
                exc.stderr,
            )
            raise InvalidGitRepositoryException(
                "VCS authorization or connection failed"
            ) from exc
        except Exception as exc:
            raise InvalidGitRepositoryException(
                "Failed to pull private repository from VCS control plane"
            ) from exc

    def get_commit_history(self, repo_path: str, limit: int = MAX_COMMITS) -> List[str]:
        """Return recent commit SHAs for backwards-compatible consumers."""
        try:
            safe_limit = max(1, min(int(limit), MAX_COMMITS))
            process = subprocess.run(
                ["git", "log", "-n", str(safe_limit), "--pretty=format:%H"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            )
            return process.stdout.splitlines()
        except Exception as exc:
            logger.warning("Could not fetch git logs in %s: %s", repo_path, exc)
            return []

    def get_source_revision(
        self,
        repo_path: str,
        commit_limit: int = MAX_COMMITS,
        changed_files_limit: int = MAX_CHANGED_FILES_PER_COMMIT,
    ) -> Dict[str, Any]:
        """Return bounded, audit-friendly commit metadata without collecting full diffs."""
        safe_commit_limit = max(1, min(int(commit_limit), MAX_COMMITS))
        safe_changed_files_limit = max(
            1,
            min(int(changed_files_limit), MAX_CHANGED_FILES_PER_COMMIT),
        )

        try:
            head_process = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            )
            head_sha = head_process.stdout.strip()

            log_process = subprocess.run(
                [
                    "git",
                    "log",
                    "-n",
                    str(safe_commit_limit),
                    "--format=%H%x1f%an%x1f%aI%x1f%s%x1e",
                ],
                cwd=repo_path,
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            )

            commits: List[Dict[str, Any]] = []
            total_additions = 0
            total_deletions = 0
            total_files_changed = 0

            for record in filter(None, log_process.stdout.split("\x1e")):
                parts = record.rstrip("\n").split("\x1f", 3)
                if len(parts) != 4:
                    continue

                sha, author, timestamp, subject = parts
                changed = self._get_changed_files(
                    repo_path,
                    sha,
                    safe_changed_files_limit,
                )
                total_additions += changed["additions"]
                total_deletions += changed["deletions"]
                total_files_changed += changed["files_changed"]

                commits.append(
                    {
                        "sha": sha.strip(),
                        "author": author.strip()[:MAX_AUTHOR_LENGTH],
                        "timestamp": timestamp.strip(),
                        "subject": subject.strip()[:MAX_SUBJECT_LENGTH],
                        "files_changed": changed["files"],
                        "files_changed_count": changed["files_changed"],
                        "additions": changed["additions"],
                        "deletions": changed["deletions"],
                    }
                )

            return {
                "head_sha": head_sha,
                "commits": commits,
                "summary": {
                    "commit_count": len(commits),
                    "files_changed": total_files_changed,
                    "additions": total_additions,
                    "deletions": total_deletions,
                },
            }
        except Exception as exc:
            logger.warning(
                "Could not collect structured Git source revision in %s: %s",
                repo_path,
                exc,
            )
            return {}

    @staticmethod
    def _get_changed_files(
        repo_path: str,
        commit_sha: str,
        limit: int,
    ) -> Dict[str, Any]:
        process = subprocess.run(
            ["git", "diff-tree", "--no-commit-id", "--numstat", "-r", commit_sha],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )

        files: List[Dict[str, Any]] = []
        additions = 0
        deletions = 0

        for line in process.stdout.splitlines()[:limit]:
            fields = line.split("\t", 2)
            if len(fields) != 3:
                continue

            raw_additions, raw_deletions, path = fields
            path = path.strip()[:MAX_PATH_LENGTH]
            try:
                file_additions = int(raw_additions)
            except ValueError:
                file_additions = 0
            try:
                file_deletions = int(raw_deletions)
            except ValueError:
                file_deletions = 0

            additions += file_additions
            deletions += file_deletions
            files.append(
                {
                    "path": path,
                    "additions": file_additions,
                    "deletions": file_deletions,
                    "binary": raw_additions == "-" or raw_deletions == "-",
                }
            )

        return {
            "files": files,
            "files_changed": len(files),
            "additions": additions,
            "deletions": deletions,
        }
