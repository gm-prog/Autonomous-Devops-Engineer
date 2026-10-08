from dataclasses import dataclass, field
from datetime import datetime

@dataclass
class HotfixProposal:
    """HotfixProposal Entity managing unified diff edits along with CI test status validations.

    Verification honesty (Phase 8.7-D.1): ``is_verified`` is True only when
    the required checks were ACTUALLY executed and passed (via
    ``mark_verified``).  ``record_claimed_verification`` is a PLACEHOLDER —
    it records that a verification pass was claimed without running any
    check, and it deliberately leaves the proposal unverified.  Callers must
    not treat a claimed pass as real verification.
    """
    id: str
    target_filepath: str
    diff_patch_payload: str
    is_verified: bool = False
    verification_claimed: bool = False
    generated_at: datetime = field(default_factory=datetime.utcnow)

    def record_claimed_verification(self) -> bool:
        """Records a CLAIMED verification pass (placeholder — no checks run).

        The proposal is NOT marked verified: this method performs no lint or
        unit checks, so pretending otherwise would be a false claim.
        """
        self.verification_claimed = True
        return self.verification_claimed

    def mark_verified(self) -> None:
        """Mark the proposal verified — only to be called AFTER the required
        lint/unit checks have actually been executed and passed."""
        self.is_verified = True
