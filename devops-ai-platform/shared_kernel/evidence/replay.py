"""Deterministic capture and replay of evidence packs (§26).

A capture bundle is the complete, self-contained input to the correlation
engine: the normalized observations, the policy parameters that were in
force, and the schema version. :func:`replay_capture` rebuilds the pack
from that bundle **without touching any external system** — it is a pure
function of the captured bytes, which is what makes it usable for
regression testing, audit, and later model comparison.

Replay reproduces ``pack_hash`` exactly. ``generated_at`` is carried in the
bundle for the record but is excluded from the hash, so replaying at a
different wall-clock time cannot change the result.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from .canonical import canonical_json, content_hash
from .correlation import (
    SUPPORTED_CORRELATION_POLICY_VERSIONS,
    CorrelationPolicy,
    OperationalCorrelationEngine,
)
from .identities import (
    DeploymentIdentity,
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
    EvidencePack,
    EvidenceProvenance,
    EvidenceStatus,
    EvidenceStrength,
    EVIDENCE_SCHEMA_VERSION,
    ObservationType,
    SourceReference,
    SourceType,
)

__all__ = [
    "CAPTURE_SCHEMA",
    "capture_inputs",
    "replay_capture",
    "rehydrate_item",
]

CAPTURE_SCHEMA = "devops.evidence-capture/1"

_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


def _parse_timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise EvidenceError(
            EvidenceErrorCode.INVALID_EVIDENCE, f"{field} must be a canonical timestamp"
        )
    try:
        return datetime.strptime(value, _TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise EvidenceError(
            EvidenceErrorCode.INVALID_EVIDENCE,
            f"{field} is not a canonical UTC timestamp: {value!r}",
        ) from exc


def capture_inputs(
    *,
    incident_id: str,
    evidence_items: Iterable[EvidenceItem],
    policy: CorrelationPolicy,
    generated_at: datetime,
    reference_time: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Serialize everything needed to reproduce a pack, and nothing else."""
    from .canonical import format_timestamp

    items = sorted(evidence_items, key=lambda item: item.evidence_id)
    bundle: Dict[str, Any] = {
        "capture_schema": CAPTURE_SCHEMA,
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "incident_id": incident_id,
        "generated_at": format_timestamp(generated_at, field="generated_at"),
        "reference_time": (
            format_timestamp(reference_time, field="reference_time")
            if reference_time is not None
            else None
        ),
        "policy": {
            "version": policy.version,
            "temporal_window_before_seconds": policy.temporal_window_before.total_seconds(),
            "temporal_window_after_seconds": policy.temporal_window_after.total_seconds(),
            "clock_skew_tolerance_seconds": policy.clock_skew_tolerance.total_seconds(),
            "stale_after_seconds": policy.stale_after.total_seconds(),
            "max_bucket_pairs": policy.max_bucket_pairs,
        },
        "evidence_items": [item.to_dict() for item in items],
    }
    bundle["capture_hash"] = content_hash(
        {key: bundle[key] for key in bundle if key != "capture_hash"}
    )
    return bundle


def rehydrate_item(data: Mapping[str, Any]) -> EvidenceItem:
    """Rebuild an :class:`EvidenceItem` from its canonical dict.

    Derived fields (``evidence_id``, ``content_hash``) are passed back in
    and re-verified by the constructor, so a tampered capture bundle fails
    loudly instead of replaying as if it were authentic.
    """
    if not isinstance(data, Mapping):
        raise EvidenceError(
            EvidenceErrorCode.INVALID_EVIDENCE, "evidence item must be a mapping"
        )
    try:
        provenance_data = data["provenance"]
        reference_data = provenance_data["source_reference"]
        provenance = EvidenceProvenance(
            source_system=SourceType(provenance_data["source_system"]),
            source_reference=SourceReference(
                object_type=reference_data["object_type"],
                object_id=reference_data["object_id"],
                uri=reference_data.get("uri"),
            ),
            retrieved_at=_parse_timestamp(
                provenance_data["retrieved_at"], "provenance.retrieved_at"
            ),
            source_api_version=provenance_data.get("source_api_version"),
            repository=_rehydrate_repository(provenance_data.get("repository")),
            commit_sha=provenance_data.get("commit_sha"),
            workflow_run_id=provenance_data.get("workflow_run_id"),
            artifact_digest=provenance_data.get("artifact_digest"),
            query=provenance_data.get("query"),
            query_hash=provenance_data.get("query_hash"),
        )
        service = _rehydrate_service(data.get("service_identity"))
        return EvidenceItem(
            observation_type=ObservationType(data["observation_type"]),
            provenance=provenance,
            observed_at=_parse_timestamp(data["observed_at"], "observed_at"),
            collected_at=_parse_timestamp(data["collected_at"], "collected_at"),
            service_identity=service,
            deployment_identity=_rehydrate_deployment(data.get("deployment_identity")),
            resource_identity=_rehydrate_runtime(data.get("resource_identity")),
            incident_id=data.get("incident_id"),
            correlation_keys=tuple(
                CorrelationKey(
                    key_type=CorrelationKeyType(key["key_type"]),
                    value=key["value"],
                    source=SourceType(key["source"]),
                )
                for key in data.get("correlation_keys", ())
            ),
            payload=dict(data.get("payload") or {}),
            status=EvidenceStatus(data.get("status", EvidenceStatus.AVAILABLE.value)),
            strength=EvidenceStrength(
                data.get("strength", EvidenceStrength.DIRECT.value)
            ),
            evidence_id=data.get("evidence_id", ""),
            content_hash=data.get("content_hash", ""),
        )
    except KeyError as exc:
        raise EvidenceError(
            EvidenceErrorCode.INVALID_EVIDENCE,
            f"captured evidence item is missing required field {exc.args[0]!r}",
        ) from exc
    except ValueError as exc:
        if isinstance(exc, EvidenceError):
            raise
        raise EvidenceError(
            EvidenceErrorCode.INVALID_EVIDENCE,
            f"captured evidence item is not valid: {exc}",
        ) from exc


def _rehydrate_repository(data: Any) -> Optional[RepositoryIdentity]:
    if not data:
        return None
    return RepositoryIdentity(
        provider=data["provider"],
        owner=data["owner"],
        repository=data["repository"],
        source_representation=data.get("source_representation"),
    )


def _rehydrate_service(data: Any) -> Optional[ServiceIdentity]:
    if not data:
        return None
    return ServiceIdentity(
        name=data["service.name"],
        environment=data["deployment.environment.name"],
        version=data.get("service.version"),
        instance_id=data.get("service.instance.id"),
    )


def _rehydrate_runtime(data: Any) -> Optional[RuntimeIdentity]:
    if not data or not any(data.values()):
        return None
    return RuntimeIdentity(
        platform=data.get("platform"),
        namespace=data.get("namespace"),
        workload=data.get("workload"),
        pod_uid=data.get("pod_uid"),
        node=data.get("node"),
        container=data.get("container"),
    )


def _rehydrate_deployment(data: Any) -> Optional[DeploymentIdentity]:
    if not data:
        return None
    return DeploymentIdentity(
        deployment_id=data["deployment_id"],
        service=_rehydrate_service(data["service"]),
        source_sha=data.get("source_sha"),
        artifact_digest=data.get("artifact_digest"),
        status=data.get("status"),
        started_at=(
            _parse_timestamp(data["started_at"], "deployment.started_at")
            if data.get("started_at")
            else None
        ),
        completed_at=(
            _parse_timestamp(data["completed_at"], "deployment.completed_at")
            if data.get("completed_at")
            else None
        ),
        repository=_rehydrate_repository(data.get("repository")),
        branch=data.get("branch"),
        workflow_id=data.get("workflow_id"),
        workflow_run_id=data.get("workflow_run_id"),
        image_reference=data.get("image_reference"),
        image_digest=data.get("image_digest"),
        builder_identity=data.get("builder_identity"),
    )


def replay_capture(bundle: Mapping[str, Any]) -> EvidencePack:
    """Regenerate an :class:`EvidencePack` from a capture bundle.

    Performs no I/O of any kind. Raises
    ``SCHEMA_VERSION_UNSUPPORTED`` / ``CORRELATION_POLICY_UNSUPPORTED``
    rather than silently replaying under different semantics than the ones
    the bundle was produced with (§25).
    """
    if bundle.get("capture_schema") != CAPTURE_SCHEMA:
        raise EvidenceError(
            EvidenceErrorCode.SCHEMA_VERSION_UNSUPPORTED,
            f"unsupported capture schema {bundle.get('capture_schema')!r}",
        )
    if bundle.get("schema_version") != EVIDENCE_SCHEMA_VERSION:
        raise EvidenceError(
            EvidenceErrorCode.SCHEMA_VERSION_UNSUPPORTED,
            f"capture targets evidence schema {bundle.get('schema_version')!r}, "
            f"this build implements {EVIDENCE_SCHEMA_VERSION!r}",
        )

    stored_hash = bundle.get("capture_hash")
    recomputed = content_hash(
        {key: bundle[key] for key in bundle if key != "capture_hash"}
    )
    if stored_hash is not None and stored_hash != recomputed:
        raise EvidenceError(
            EvidenceErrorCode.INVALID_EVIDENCE,
            "capture bundle hash mismatch (the bundle was altered)",
        )

    policy_data = bundle.get("policy") or {}
    policy = CorrelationPolicy(
        version=policy_data.get("version", ""),
        temporal_window_before=timedelta(
            seconds=float(policy_data.get("temporal_window_before_seconds", 0))
        ),
        temporal_window_after=timedelta(
            seconds=float(policy_data.get("temporal_window_after_seconds", 0))
        ),
        clock_skew_tolerance=timedelta(
            seconds=float(policy_data.get("clock_skew_tolerance_seconds", 0))
        ),
        stale_after=timedelta(
            seconds=float(policy_data.get("stale_after_seconds", 0))
        ),
        max_bucket_pairs=int(policy_data.get("max_bucket_pairs", 10_000)),
    )
    if not policy.version:
        raise EvidenceError(
            EvidenceErrorCode.CORRELATION_POLICY_UNSUPPORTED,
            "capture bundle does not name a correlation policy version",
        )
    if policy.version not in SUPPORTED_CORRELATION_POLICY_VERSIONS:
        raise EvidenceError(
            EvidenceErrorCode.CORRELATION_POLICY_UNSUPPORTED,
            "capture bundle was produced under correlation policy "
            f"{policy.version!r}, which this build does not implement",
            supported=sorted(SUPPORTED_CORRELATION_POLICY_VERSIONS),
        )

    items = [rehydrate_item(data) for data in bundle.get("evidence_items", ())]
    engine = OperationalCorrelationEngine(policy=policy)
    return engine.correlate(
        incident_id=bundle["incident_id"],
        evidence_items=items,
        generated_at=_parse_timestamp(bundle["generated_at"], "generated_at"),
        reference_time=(
            _parse_timestamp(bundle["reference_time"], "reference_time")
            if bundle.get("reference_time")
            else None
        ),
    )
