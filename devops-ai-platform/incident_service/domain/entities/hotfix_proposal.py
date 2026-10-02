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
    # Phase 6.2: approval + controlled execution lifecycle (additive)
    approved_by: str = ""
    approved_at: Optional[datetime] = None
    approval_hash: str = ""
    execution_id: str = ""
    executed_at: Optional[datetime] = None
    commit_sha: str = ""
    branch_name: str = ""
    execution_attempts: int = 0
    last_failure_stage: str = ""
    last_failure_reason: str = ""
    # Phase 6.2.1: durable execution coordination (lease is source-of-truth
    # for ownership; execution_stage is the persisted recovery cursor).
    lease_owner: str = ""
    lease_acquired_at: Optional[datetime] = None
    lease_expires_at: Optional[datetime] = None
    last_heartbeat_at: Optional[datetime] = None
    execution_stage: str = ""

    def to_dict(self) -> dict:
        """JSON-safe projection including every §12 + §6.2 field."""
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
            "approved_by": self.approved_by,
            "approved_at": self.approved_at.isoformat() if self.approved_at else None,
            "approval_hash": self.approval_hash,
            "execution_id": self.execution_id,
            "executed_at": self.executed_at.isoformat() if self.executed_at else None,
            "commit_sha": self.commit_sha,
            "branch_name": self.branch_name,
            "execution_attempts": int(self.execution_attempts),
            "last_failure_stage": self.last_failure_stage,
            "last_failure_reason": self.last_failure_reason,
            "lease_owner": self.lease_owner,
            "lease_acquired_at": (
                self.lease_acquired_at.isoformat()
                if self.lease_acquired_at
                else None
            ),
            "lease_expires_at": (
                self.lease_expires_at.isoformat()
                if self.lease_expires_at
                else None
            ),
            "last_heartbeat_at": (
                self.last_heartbeat_at.isoformat()
                if self.last_heartbeat_at
                else None
            ),
            "execution_stage": self.execution_stage,
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
