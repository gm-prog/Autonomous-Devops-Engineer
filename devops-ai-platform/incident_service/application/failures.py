"""Typed application failures for the Phase 6.1 proposal pipeline (§25).

Every failure mode gets its own type so callers (REST layer, tests,
future Phase 6.2 executors) never have to decode a generic ``False`` or a
bare string. Presentation maps each type to a deliberate HTTP status.
"""


class Phase6PipelineError(Exception):
    """Base class for typed Phase 6.1 application failures."""


class IncidentNotFound(Phase6PipelineError):
    """The referenced incident does not exist."""


class EvidenceUnavailable(Phase6PipelineError):
    """The incident's evidence pack could not be built."""


class DeploymentEvidenceUnavailable(Phase6PipelineError):
    """Deployment evidence could not be collected/inspected."""


class RcaGenerationFailed(Phase6PipelineError):
    """The RCA provider could not produce a result (unavailable/broken)."""


class InvalidRcaResult(Phase6PipelineError):
    """Provider output failed the structured RCA schema (fail closed)."""


class TargetBindingFailed(Phase6PipelineError):
    """Requested target identity is not provable from trusted evidence."""


class ProposalValidationFailed(Phase6PipelineError):
    """Deterministic patch/proposal validation rejected the proposal."""


class ProposalPersistenceFailed(Phase6PipelineError):
    """The proposal could not be persisted."""
