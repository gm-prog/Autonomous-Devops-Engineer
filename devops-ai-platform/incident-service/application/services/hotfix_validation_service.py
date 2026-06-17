from abc import ABC, abstractmethod
from typing import Tuple, List
import logging
from ...domain.entities.hotfix_proposal import HotfixProposal

logger = logging.getLogger("HotfixValidationService")

class RejectionRule(ABC):
    @abstractmethod
    def evaluate(self, hotfix: HotfixProposal, confidence_score: float) -> Tuple[bool, str]:
        """Returns (passes_rule, reason_if_rejected)"""
        pass

class DiffSizeRule(RejectionRule):
    """Rejects patches modifying more than 1000 lines of product code because of automated hazards."""
    def __init__(self, max_allowed_lines: int = 1000):
        self.max_lines = max_allowed_lines

    def evaluate(self, hotfix: HotfixProposal, confidence_score: float) -> Tuple[bool, str]:
        diff_lines = hotfix.diff_patch_payload.splitlines()
        if len(diff_lines) > self.max_lines:
            return False, f"Diff size exceed thresholds: {len(diff_lines)} lines changed (Max: {self.max_lines})"
        return True, ""

class SecurityFilesRule(RejectionRule):
    """Prevents automation from tampering with critical authentication, keys, or decryption libraries."""
    def __init__(self):
        self.forbidden_keywords = ["auth", "crypt", "vault", "password", "security", "token"]

    def evaluate(self, hotfix: HotfixProposal, confidence_score: float) -> Tuple[bool, str]:
        target = hotfix.target_filepath.lower()
        for word in self.forbidden_keywords:
            if word in target:
                return False, f"Security violation sandbox triggers. Hotfix is editing critical path: {hotfix.target_filepath}"
        return True, ""

class ConfidenceScoreRule(RejectionRule):
    """Rejects fixes if LLM reasoning metrics yield a score lower than 75% accuracy assertions."""
    def __init__(self, min_score: float = 0.75):
        self.min_score = min_score

    def evaluate(self, hotfix: HotfixProposal, confidence_score: float) -> Tuple[bool, str]:
        if confidence_score < self.min_score:
            return False, f"Confidence score validation failed: {confidence_score * 100:.1f}% (Required: {self.min_score * 100:.1f}%)"
        return True, ""

class HotfixValidationService:
    """
    Decoupled rule validation checking AI actions against enterprise policies,
    minimizing production anomalies.
    """
    def __init__(self, rules: List[RejectionRule] = None):
        self.rules = rules or [
            DiffSizeRule(),
            SecurityFilesRule(),
            ConfidenceScoreRule()
        ]

    def validate_patch(self, hotfix: HotfixProposal, confidence: float) -> Tuple[bool, List[str]]:
        rejection_reasons = []
        for rule in self.rules:
            passes, reason = rule.evaluate(hotfix, confidence)
            if not passes:
                rejection_reasons.append(reason)
                
        if rejection_reasons:
            logger.warning(f"[HOTFIX_REJECTED] Validation failed for Patch {hotfix.id}. Reasons: {rejection_reasons}")
            return False, rejection_reasons
            
        logger.info(f"[HOTFIX_APPROVED] Patch {hotfix.id} successfully cleared safety guidelines.")
        return True, []
