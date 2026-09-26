from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass
class HotfixProposal:
    """A reviewable remediation proposal backed by deterministic validation."""

    id: str
    target_filepath: str
    diff_patch_payload: str
    is_verified: bool = False
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    pull_request_url: Optional[str] = None
    source_sha: Optional[str] = None

    def apply_verification_pass(self) -> bool:
        """Verify a single-file unified diff; execution belongs to a separate executor."""
        path = self.target_filepath.replace("\\", "/").strip()
        patch = self.diff_patch_payload.strip()

        if not path or not patch:
            self.is_verified = False
            return False
        if path.startswith("/") or ".." in path.split("/"):
            self.is_verified = False
            return False

        lines = patch.splitlines()
        old_headers = [
            (index, line[6:].strip())
            for index, line in enumerate(lines)
            if line.startswith("--- a/")
        ]
        new_headers = [
            (index, line[6:].strip())
            for index, line in enumerate(lines)
            if line.startswith("+++ b/")
        ]

        if len(old_headers) != 1 or len(new_headers) != 1:
            self.is_verified = False
            return False

        old_index, old_path = old_headers[0]
        new_index, new_path = new_headers[0]
        if new_index != old_index + 1:
            self.is_verified = False
            return False
        if old_path != path or new_path != path:
            self.is_verified = False
            return False

        has_hunk = any(line.startswith("@@") for line in lines[new_index + 1 :])
        self.is_verified = has_hunk
        return self.is_verified
