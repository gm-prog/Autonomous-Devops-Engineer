import os
import shutil
import tempfile
import uuid
from pathlib import Path
from typing import Any, Dict, List

from application.services.ast_parser_service import ASTParserService
from domain.entities.code_file import CodeFile

try:
    from .infrastructure.git.git_ssh_client import GitSSHClient
except ImportError:
    from infrastructure.git.git_ssh_client import GitSSHClient


IGNORED_DIRS = {
    ".git", ".gradle", ".idea", ".venv", "venv", "node_modules",
    "dist", "build", "target", "__pycache__", ".next", ".tox",
    ".pytest_cache", "coverage"
}
MAX_FILES = 80
MAX_FILE_BYTES = 16 * 1024
MAX_TOTAL_BYTES = 512 * 1024
TEXT_SUFFIXES = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".kt", ".kts",
    ".go", ".rs", ".rb", ".php", ".cs", ".json", ".yaml", ".yml",
    ".toml", ".ini", ".cfg", ".conf", ".txt", ".md", ".xml",
    ".properties", ".gradle", ".tf", ".tfvars", ".sh"
}

class RepositoryAnalyzer:
    """Clones a repository, performs bounded source inspection, and returns analysis input."""

    def __init__(self, git_client: GitSSHClient | None = None, parser: ASTParserService | None = None):
        self.git_client = git_client or GitSSHClient()
        self.parser = parser or ASTParserService()

    def analyze(self, repo_url: str, repo_name: str) -> Dict[str, Any]:
        temp_dir = tempfile.mkdtemp(prefix="devops-repo-")
        clone_dir = os.path.join(temp_dir, "source")
        try:
            self.git_client.clone_repository(repo_url, clone_dir)
            files = self._collect_files(Path(clone_dir))
            tech_stack = self.parser.evaluate_codebase(files)
            commits = self.git_client.get_commit_history(clone_dir, limit=5)

            source_files = [
                {
                    "path": f.filepath,
                    "language": f.language,
                    "size_bytes": f.size_bytes,
                    "content": f.content,
                }
                for f in files
            ]

            return {
                "name": repo_name,
                "url": repo_url,
                "total_files": len(files),
                "tech_stack": {
                    "primary_language": tech_stack.primary_language,
                    "frameworks": tech_stack.detected_frameworks,
                    "has_dockerfile": tech_stack.has_dockerfile,
                    "has_k8s_manifests": tech_stack.has_k8s_manifests,
                },
                "recent_commits": commits,
                "files": source_files,
            }
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def _collect_files(self, root: Path) -> List[CodeFile]:
        results: List[CodeFile] = []
        total_bytes = 0

        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            if any(part in IGNORED_DIRS for part in path.parts):
                continue

            relative = path.relative_to(root).as_posix()
            if relative.startswith(".git/"):
                continue

            suffix = path.suffix.lower()
            if path.name != "Dockerfile" and suffix not in TEXT_SUFFIXES:
                continue

            try:
                size = path.stat().st_size
                if size <= 0 or size > MAX_FILE_BYTES:
                    continue
                if total_bytes + size > MAX_TOTAL_BYTES:
                    break

                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            total_bytes += size
            language = self.parser.detect_language(relative)
            results.append(
                CodeFile(
                    id=str(uuid.uuid4()),
                    filepath=relative,
                    language=language,
                    size_bytes=size,
                    content=content,
                )
            )
            if len(results) >= MAX_FILES:
                break

        return results
