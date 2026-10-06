"""Source adapters: raw project data in, normalized evidence out (§31).

Adapters do exactly one job — translate a source-specific record into the
canonical :class:`~shared_kernel.evidence.model.EvidenceItem` contract.
They do **not** correlate, do not persist, and do not reach the network.
Keeping ingestion, normalization, correlation and persistence separate is
what makes the layer replayable and testable offline (§32).

Phase G.1 deliberately ships adapters only for data this project already
has: incidents, deployment provenance, Git/GitHub references, monitoring
samples and validation results. Vendor backends (Datadog, Grafana,
Prometheus remote, Elastic, cloud APIs) are future adapters behind the same
interface — the architecture is pluggable, the integrations are not written
yet, and nothing here pretends otherwise.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from ..domain.provenance import ProvenanceError, verify_provenance_record
from .canonical import ensure_utc
from .identities import (
    DeploymentIdentity,
    IdentityError,
    RepositoryIdentity,
    RuntimeIdentity,
    ServiceIdentity,
)
from .model import (
    CorrelationKey,
    CorrelationKeyType,
    EvidenceError,
    EvidenceErrorCode,
    EvidenceItem,
    EvidenceProvenance,
    EvidenceStatus,
    EvidenceStrength,
    ObservationType,
    SourceReference,
    SourceType,
)

__all__ = [
    "EvidenceSourceAdapter",
    "IncidentEvidenceSource",
    "DeploymentEvidenceSource",
    "GitHubEvidenceSource",
    "MonitoringEvidenceSource",
    "ValidationEvidenceSource",
]


class EvidenceSourceAdapter(ABC):
    """Narrow port every evidence source implements."""

    #: The trusted subsystem this adapter speaks for.
    source_type: SourceType

    @abstractmethod
    def collect(self, *args: Any, **kwargs: Any) -> Sequence[EvidenceItem]:
        """Return normalized evidence. Never correlates, never mutates."""

    # -- shared helpers ------------------------------------------------

    def _provenance(
        self,
        *,
        object_type: str,
        object_id: str,
        retrieved_at: datetime,
        uri: Optional[str] = None,
        api_version: Optional[str] = None,
        repository: Optional[RepositoryIdentity] = None,
        commit_sha: Optional[str] = None,
        workflow_run_id: Optional[str] = None,
        artifact_digest: Optional[str] = None,
        query: Optional[str] = None,
    ) -> EvidenceProvenance:
        return EvidenceProvenance(
            source_system=self.source_type,
            source_reference=SourceReference(
                object_type=object_type, object_id=object_id, uri=uri
            ),
            retrieved_at=retrieved_at,
            source_api_version=api_version,
            repository=repository,
            commit_sha=commit_sha,
            workflow_run_id=workflow_run_id,
            artifact_digest=artifact_digest,
            query=query,
        )

    def _key(self, key_type: CorrelationKeyType, value: Any) -> Optional[CorrelationKey]:
        """Build a correlation key, or ``None`` when the value is absent.

        Absent values produce no key at all — they are never turned into a
        placeholder string that would then join against other placeholders.
        """
        if value is None:
            return None
        text = str(value).strip()
        if not text:
            return None
        return CorrelationKey(key_type=key_type, value=text, source=self.source_type)

    def _keys(self, pairs: Iterable[Tuple[CorrelationKeyType, Any]]) -> Tuple[CorrelationKey, ...]:
        built = (self._key(key_type, value) for key_type, value in pairs)
        return tuple(key for key in built if key is not None)

    @staticmethod
    def _service(
        name: Any, environment: Any, version: Any = None, instance_id: Any = None
    ) -> ServiceIdentity:
        try:
            return ServiceIdentity(
                name=name, environment=environment, version=version, instance_id=instance_id
            )
        except IdentityError as exc:
            raise EvidenceError(EvidenceErrorCode.INVALID_IDENTITY, str(exc)) from exc


class IncidentEvidenceSource(EvidenceSourceAdapter):
    """Normalizes incident records and legacy ``IncidentEvidence`` rows.

    The pre-existing ``incident_service`` entity uses the weak field names
    ``kind`` / ``source`` / ``payload``. Rather than changing that entity
    (and breaking callers), this adapter is the documented
    legacy-field → canonical-model boundary required by §47.
    """

    source_type = SourceType.INCIDENT_SERVICE

    def collect(
        self,
        *,
        incident_id: str,
        service_name: str,
        environment: str,
        observed_at: datetime,
        collected_at: datetime,
        title: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        trace_id: Optional[str] = None,
        request_id: Optional[str] = None,
        deployment_id: Optional[str] = None,
    ) -> Sequence[EvidenceItem]:
        service = self._service(service_name, environment)
        payload: Dict[str, Any] = {}
        # explicit, named fields only - never a generic "data" blob
        if title is not None:
            payload["title"] = title
        if severity is not None:
            payload["severity"] = severity
        if status is not None:
            payload["lifecycle_status"] = status

        item = EvidenceItem(
            observation_type=ObservationType.INCIDENT,
            provenance=self._provenance(
                object_type="incident",
                object_id=incident_id,
                retrieved_at=collected_at,
            ),
            observed_at=observed_at,
            collected_at=collected_at,
            service_identity=service,
            incident_id=incident_id,
            correlation_keys=self._keys(
                (
                    (CorrelationKeyType.INCIDENT_ID, incident_id),
                    (CorrelationKeyType.SERVICE_NAME, service.name),
                    (CorrelationKeyType.SERVICE_SCOPE, service.scope),
                    (CorrelationKeyType.ENVIRONMENT, service.environment),
                    (CorrelationKeyType.TRACE_ID, trace_id),
                    (CorrelationKeyType.REQUEST_ID, request_id),
                    (CorrelationKeyType.DEPLOYMENT_ID, deployment_id),
                )
            ),
            payload=payload,
            status=EvidenceStatus.AVAILABLE,
            strength=EvidenceStrength.DIRECT,
        )
        return (item,)

    def from_legacy_evidence(
        self,
        legacy: Any,
        *,
        incident_id: str,
        service_name: str,
        environment: str,
        collected_at: datetime,
    ) -> EvidenceItem:
        """Adapt a legacy ``IncidentEvidence`` instance (§47).

        The legacy ``kind`` string is mapped onto the controlled
        :class:`ObservationType` vocabulary; an unmappable kind is rejected
        rather than silently bucketed as "other".
        """
        kind = str(getattr(legacy, "kind", "")).strip().upper()
        mapping = {
            "OBSERVATION": ObservationType.METRIC,
            "METRIC": ObservationType.METRIC,
            "LOG": ObservationType.LOG,
            "TRACE": ObservationType.TRACE,
            "HEALTH_CHECK": ObservationType.HEALTH_CHECK,
            "VALIDATION": ObservationType.VALIDATION_RESULT,
            "DEPLOYMENT": ObservationType.DEPLOYMENT,
        }
        if kind not in mapping:
            raise EvidenceError(
                EvidenceErrorCode.INVALID_EVIDENCE,
                f"legacy evidence kind {kind!r} has no canonical observation "
                "type; add an explicit mapping instead of guessing",
            )
        observed_at = getattr(legacy, "observed_at", None)
        if observed_at is None:
            raise EvidenceError(
                EvidenceErrorCode.INVALID_EVIDENCE,
                "legacy evidence has no observed_at",
            )
        service = self._service(service_name, environment)
        legacy_id = str(getattr(legacy, "id", "") or "").strip()
        if not legacy_id:
            # reject rather than coerce (§30): inventing "unknown-legacy-row"
            # would fabricate an identifier that no source ever asserted
            raise EvidenceError(
                EvidenceErrorCode.INVALID_EVIDENCE,
                "legacy incident evidence has no id; it cannot be given a "
                "source reference",
            )
        return EvidenceItem(
            observation_type=mapping[kind],
            provenance=self._provenance(
                object_type="legacy-incident-evidence",
                object_id=legacy_id,
                retrieved_at=collected_at,
            ),
            observed_at=observed_at,
            collected_at=collected_at,
            service_identity=service,
            incident_id=incident_id,
            correlation_keys=self._keys(
                (
                    (CorrelationKeyType.INCIDENT_ID, incident_id),
                    (CorrelationKeyType.SERVICE_SCOPE, service.scope),
                    (CorrelationKeyType.ENVIRONMENT, service.environment),
                )
            ),
            payload=dict(getattr(legacy, "payload", {}) or {}),
            strength=EvidenceStrength.DERIVED,
        )


class DeploymentEvidenceSource(EvidenceSourceAdapter):
    """Normalizes deployment runs, including Stage-5 provenance records."""

    source_type = SourceType.DEPLOYMENT_SERVICE

    def collect(
        self,
        *,
        deployment_id: str,
        service_name: str,
        environment: str,
        observed_at: datetime,
        collected_at: datetime,
        source_sha: Optional[str] = None,
        artifact_digest: Optional[str] = None,
        status: Optional[str] = None,
        repository: Optional[str] = None,
        workflow_run_id: Optional[str] = None,
        image_digest: Optional[str] = None,
        incident_id: Optional[str] = None,
    ) -> Sequence[EvidenceItem]:
        service = self._service(service_name, environment)
        repo_identity = (
            RepositoryIdentity.parse(repository) if repository is not None else None
        )
        try:
            identity = DeploymentIdentity(
                deployment_id=deployment_id,
                service=service,
                source_sha=source_sha,
                artifact_digest=artifact_digest,
                status=status,
                started_at=observed_at,
                repository=repo_identity,
                workflow_run_id=workflow_run_id,
                image_digest=image_digest,
            )
        except IdentityError as exc:
            raise EvidenceError(EvidenceErrorCode.INVALID_IDENTITY, str(exc)) from exc

        payload: Dict[str, Any] = {}
        if status is not None:
            payload["deployment_status"] = status

        item = EvidenceItem(
            observation_type=ObservationType.DEPLOYMENT,
            provenance=self._provenance(
                object_type="deployment-run",
                object_id=deployment_id,
                retrieved_at=collected_at,
                repository=repo_identity,
                commit_sha=identity.source_sha,
                workflow_run_id=workflow_run_id,
                artifact_digest=identity.artifact_digest,
            ),
            observed_at=observed_at,
            collected_at=collected_at,
            service_identity=service,
            deployment_identity=identity,
            incident_id=incident_id,
            correlation_keys=self._keys(
                (
                    (CorrelationKeyType.DEPLOYMENT_ID, deployment_id),
                    (CorrelationKeyType.SERVICE_SCOPE, service.scope),
                    (CorrelationKeyType.SERVICE_NAME, service.name),
                    (CorrelationKeyType.ENVIRONMENT, service.environment),
                    (CorrelationKeyType.COMMIT_SHA, identity.source_sha),
                    (
                        CorrelationKeyType.REPOSITORY,
                        repo_identity.qualified_name if repo_identity else None,
                    ),
                    (CorrelationKeyType.WORKFLOW_RUN_ID, workflow_run_id),
                    (CorrelationKeyType.INCIDENT_ID, incident_id),
                )
            ),
            payload=payload,
            strength=EvidenceStrength.DIRECT,
        )
        return (item,)

    def from_provenance_record(
        self,
        record: Mapping[str, Any],
        *,
        service_name: str,
        environment: str,
        observed_at: datetime,
        collected_at: datetime,
    ) -> EvidenceItem:
        """Normalize a verified Stage-5 deployment provenance record.

        The record is verified with the platform's existing
        :func:`verify_provenance_record` first; an unverifiable record
        becomes ``INVALID`` evidence rather than trusted provenance.
        """
        try:
            verify_provenance_record(dict(record))
        except ProvenanceError as exc:
            raise EvidenceError(
                EvidenceErrorCode.INVALID_PROVENANCE,
                f"deployment provenance record rejected: {exc}",
            ) from exc
        return self.collect(
            deployment_id=str(record["deployment_run_id"]),
            service_name=service_name,
            environment=environment,
            observed_at=observed_at,
            collected_at=collected_at,
            source_sha=str(record["source_sha"]),
            status=str(record["state"]),
            repository=str(record["repository_name"]),
        )[0]


class GitHubEvidenceSource(EvidenceSourceAdapter):
    """Normalizes GitHub/Git objects into repository+commit evidence."""

    source_type = SourceType.GITHUB

    def collect(
        self,
        *,
        repository: str,
        commit_sha: str,
        observed_at: datetime,
        collected_at: datetime,
        event_type: str = "commit",
        api_object_id: Optional[str] = None,
        api_version: Optional[str] = "2022-11-28",
        workflow_run_id: Optional[str] = None,
        message: Optional[str] = None,
        incident_id: Optional[str] = None,
    ) -> Sequence[EvidenceItem]:
        repo_identity = RepositoryIdentity.parse(repository)
        observation = (
            ObservationType.GIT_COMMIT
            if event_type == "commit"
            else ObservationType.GITHUB_EVENT
        )
        payload: Dict[str, Any] = {"event_type": event_type}
        if message is not None:
            # Commit messages are untrusted text. They are stored as data,
            # never interpreted (§33).
            payload["commit_message"] = message

        item = EvidenceItem(
            observation_type=observation,
            provenance=self._provenance(
                object_type=f"github-{event_type}",
                object_id=api_object_id or f"{repo_identity.canonical_name}@{commit_sha}",
                retrieved_at=collected_at,
                uri=(
                    f"https://github.com/{repo_identity.canonical_name}/commit/{commit_sha}"
                    if observation is ObservationType.GIT_COMMIT
                    else None
                ),
                api_version=api_version,
                repository=repo_identity,
                commit_sha=commit_sha,
                workflow_run_id=workflow_run_id,
            ),
            observed_at=observed_at,
            collected_at=collected_at,
            incident_id=incident_id,
            correlation_keys=self._keys(
                (
                    (CorrelationKeyType.REPOSITORY, repo_identity.qualified_name),
                    (CorrelationKeyType.COMMIT_SHA, commit_sha),
                    (CorrelationKeyType.WORKFLOW_RUN_ID, workflow_run_id),
                    (CorrelationKeyType.INCIDENT_ID, incident_id),
                )
            ),
            payload=payload,
            strength=EvidenceStrength.DIRECT,
        )
        return (item,)


class MonitoringEvidenceSource(EvidenceSourceAdapter):
    """Normalizes metric / log / trace samples already available in-platform."""

    source_type = SourceType.MONITORING

    def collect(
        self,
        *,
        observation_type: ObservationType,
        service_name: str,
        environment: str,
        observed_at: datetime,
        collected_at: datetime,
        metric_name: Optional[str] = None,
        metric_value: Optional[float] = None,
        metric_unit: Optional[str] = None,
        log_level: Optional[str] = None,
        log_message: Optional[str] = None,
        trace_id: Optional[str] = None,
        span_id: Optional[str] = None,
        deployment_id: Optional[str] = None,
        incident_id: Optional[str] = None,
        instance_id: Optional[str] = None,
        pod_uid: Optional[str] = None,
        status: EvidenceStatus = EvidenceStatus.AVAILABLE,
    ) -> Sequence[EvidenceItem]:
        if observation_type not in (
            ObservationType.METRIC,
            ObservationType.LOG,
            ObservationType.TRACE,
            ObservationType.HEALTH_CHECK,
        ):
            raise EvidenceError(
                EvidenceErrorCode.INVALID_EVIDENCE,
                f"{observation_type.value} is not a monitoring observation",
            )
        service = self._service(
            service_name, environment, instance_id=instance_id
        )
        payload: Dict[str, Any] = {}
        if status is EvidenceStatus.AVAILABLE:
            if metric_name is not None:
                payload["metric_name"] = metric_name
            if metric_value is not None:
                payload["metric_value"] = metric_value
            if metric_unit is not None:
                payload["metric_unit"] = metric_unit
            if log_level is not None:
                payload["log_level"] = log_level
            if log_message is not None:
                payload["log_message"] = log_message

        runtime = (
            RuntimeIdentity(platform="kubernetes", pod_uid=pod_uid)
            if pod_uid is not None
            else None
        )
        item = EvidenceItem(
            observation_type=observation_type,
            provenance=self._provenance(
                object_type=observation_type.value.lower(),
                object_id=(
                    f"{service.scope}/{metric_name or observation_type.value.lower()}"
                    f"/{int(ensure_utc(observed_at).timestamp() * 1_000_000)}"
                ),
                retrieved_at=collected_at,
            ),
            observed_at=observed_at,
            collected_at=collected_at,
            service_identity=service,
            resource_identity=runtime,
            incident_id=incident_id,
            correlation_keys=self._keys(
                (
                    (CorrelationKeyType.SERVICE_SCOPE, service.scope),
                    (CorrelationKeyType.SERVICE_NAME, service.name),
                    (CorrelationKeyType.ENVIRONMENT, service.environment),
                    (CorrelationKeyType.SERVICE_INSTANCE_ID, instance_id),
                    (CorrelationKeyType.TRACE_ID, trace_id),
                    (CorrelationKeyType.SPAN_ID, span_id),
                    (CorrelationKeyType.DEPLOYMENT_ID, deployment_id),
                    (CorrelationKeyType.POD_UID, pod_uid),
                    (CorrelationKeyType.INCIDENT_ID, incident_id),
                )
            ),
            payload=payload,
            status=status,
            strength=EvidenceStrength.DIRECT,
        )
        return (item,)


class ValidationEvidenceSource(EvidenceSourceAdapter):
    """Normalizes validation / E2E results already produced by the platform."""

    source_type = SourceType.E2E

    def collect(
        self,
        *,
        validation_id: str,
        service_name: str,
        environment: str,
        observed_at: datetime,
        collected_at: datetime,
        outcome: str,
        deployment_id: Optional[str] = None,
        incident_id: Optional[str] = None,
        detail: Optional[Mapping[str, Any]] = None,
    ) -> Sequence[EvidenceItem]:
        service = self._service(service_name, environment)
        payload: Dict[str, Any] = {"outcome": outcome}
        if detail:
            payload["detail"] = dict(detail)
        item = EvidenceItem(
            observation_type=ObservationType.VALIDATION_RESULT,
            provenance=self._provenance(
                object_type="validation-run",
                object_id=validation_id,
                retrieved_at=collected_at,
            ),
            observed_at=observed_at,
            collected_at=collected_at,
            service_identity=service,
            incident_id=incident_id,
            correlation_keys=self._keys(
                (
                    (CorrelationKeyType.SERVICE_SCOPE, service.scope),
                    (CorrelationKeyType.ENVIRONMENT, service.environment),
                    (CorrelationKeyType.DEPLOYMENT_ID, deployment_id),
                    (CorrelationKeyType.INCIDENT_ID, incident_id),
                )
            ),
            payload=payload,
            strength=EvidenceStrength.DERIVED,
        )
        return (item,)
