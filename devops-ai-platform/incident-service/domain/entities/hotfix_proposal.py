from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass
class HotfixProposal:
    """A reviewable remediation proposal backed by a deterministic patch shape check."""

    id: str
    target_filepath: str
    diff_patch_payload: str
    is_verified: bool = False
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    pull_request_url: Optional[str] = None

    def apply_verification_pass(self) -> bool:
        """Verify patch structure only; compilation/execution belongs to a separate executor."""
        path = self.target_filepath.replace("\\", "/").strip()
        patch = self.diff_patch_payload.strip()

        if not path or not patch:
            return False
        if path.startswith("/") or ".." in path.split("/"):
            return False

        lines = patch.splitlines()
        has_hunk = any(line.startswith("@@") for line in lines)
        old_marker = any(line.startswith("--- a/") for line in lines)
        new_marker = any(line.startswith("+++ b/") for line in lines)
        target_marker = f"+++ b/{path}" in lines

        self.is_verified = bool(has_hunk and old_marker and new_marker and target_marker)
        return self.is_verified
