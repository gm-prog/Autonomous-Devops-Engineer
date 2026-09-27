from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional


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
    # Phase 6.1 (§12): structured proposal identity. Defaults keep legacy
    # construction sites (execution path, old persisted rows) working.
    incident_id: str = ""
    repository: str = ""
    evidence_refs: List[str] = field(default_factory=list)
    validation_plan: List[str] = field(default_factory=list)
    risk_class: str = "UNSPECIFIED"
    proposal_hash: str = ""
    status: str = "PROPOSED"
    blocked_reason: str = ""

    def to_dict(self) -> dict:
        """JSON-safe projection including every §12 field."""
        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "target_filepath": self.target_filepath,
            "diff_patch_payload": self.diff_patch_payload,
            "is_verified": self.is_verified,
            "generated_at": self.generated_at.isoformat(),
            "pull_request_url": self.pull_request_url,
            "source_sha": self.source_sha,
            "repository": self.repository,
            "evidence_refs": list(self.evidence_refs),
            "validation_plan": list(self.validation_plan),
            "risk_class": self.risk_class,
            "proposal_hash": self.proposal_hash,
            "status": self.status,
            "blocked_reason": self.blocked_reason,
        }

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
