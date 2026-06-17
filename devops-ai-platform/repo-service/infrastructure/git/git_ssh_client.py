import os
import subprocess
import logging
from typing import Optional, List
from pathlib import Path
from ...domain.exceptions import InvalidGitRepositoryException

logger = logging.getLogger("GitSSHClient")

class GitSSHClient:
    """Provides secure, credential-based clones of private enterprise code hosting sites."""
    def __init__(self, private_key_path: Optional[str] = None):
        self.pkey = private_key_path or os.getenv("DEVOPS_SSH_KEY_PATH", "")

    def clone_repository(self, repo_url: str, dest_dir: str) -> bool:
        logger.info(f"Cloning codebase from private host: {repo_url} into local cache namespace {dest_dir}")
        
        # Check environment and setup SSH command override
        env = os.environ.copy()
        if self.pkey:
            if not os.path.exists(self.pkey):
                logger.warning(f"Configured SSH key path {self.pkey} does not exist. Proceeding with fallback keys.")
            env["GIT_SSH_COMMAND"] = f"ssh -i {self.pkey} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
        else:
            env["GIT_SSH_COMMAND"] = "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

        try:
            # Execute actual git subprocess with a defensive 120-second timeout
            process = subprocess.run(
                ["git", "clone", repo_url, dest_dir],
                capture_output=True,
                text=True,
                check=True,
                env=env,
                timeout=120
            )
            logger.info("Clone successfully processed and cataloged.")
            return True
        except subprocess.TimeoutExpired as e:
            logger.error(f"Git clone operation timed out after 120 seconds: {e}")
            raise InvalidGitRepositoryException(f"Repository clone exceeded timeout limits (120s): {repo_url}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Git execution failed standard error limits code {e.returncode}: {e.stderr}")
            raise InvalidGitRepositoryException(f"VCS authorization or connection failed: {e.stderr}")
        except Exception as e:
            raise InvalidGitRepositoryException(f"Failed to pull private repository from VCS control plane: {str(e)}")

    def get_commit_history(self, repo_path: str, limit: int = 10) -> List[str]:
        """Runs check on the cloned path returning list of commit shas."""
        try:
            process = subprocess.run(
                ["git", "log", f"-n {limit}", "--pretty=format:%H"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                check=True,
                timeout=10
            )
            return process.stdout.splitlines()
        except Exception as e:
            logger.warning(f"Could not fetch git logs in {repo_path}: {e}")
            return []

