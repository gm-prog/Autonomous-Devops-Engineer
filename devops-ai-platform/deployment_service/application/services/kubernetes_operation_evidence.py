"""P2.1 — durable Kubernetes operation provenance (bounded, monotonic).

Why this module exists
======================

``run.execution["kubernetes_apply"]`` is written in memory only after
``KubectlRunnerService.apply()`` returns, so a worker that dies between the
sandbox handoff and the next fenced commit leaves a durable record that
cannot distinguish "Kubernetes was never reached" from "Kubernetes may have
mutated". Absence of the result is therefore NOT proof of no handoff.

This module defines a small, versioned, BOUNDED evidence structure that is
persisted inside the run document by the same fenced commit that guards
state (no second Redis journal — the apply writer IS the fence owner, so
the P1-2 journal rationale does not transfer). The engine calls these
helpers; the runner only hands trusted metadata across the boundary.

What the evidence answers
=========================

A committed attempt record answers exactly one question: "did this run hand
an apply invocation to the sandbox?" It is provenance, NOT authorization:
``may_have_mutated`` may never be used to select or authorize an automatic
``kubectl rollout undo`` (see the 2026-11-14 research amendment —
conditional current-resource authorization is P2.2 and does not exist in
P2.1).

Schema (schema_version 1)::

    {
      "schema_version": 1,
      "may_have_mutated": true,          # monotonic run-scalar
      "attempt_count": 1,                # monotonic counter
      "resources": [ ... <= 32 ... ],    # non-evictable per-resource summaries
      "attempts":   [ ... <= 16 ... ],   # detailed, bounded
      "blocked_reason": "..."            # only when a capacity refusal occurred
    }

Attempt lifecycle: ``HANDOFF_PENDING`` -> ``RESULT_RECORDED``. A crash after
the handoff commit leaves ``HANDOFF_PENDING`` durably; uncertainty is never
downgraded to "not attempted".

Bounded on purpose (host-owned constants, not caller-controlled): a worker
that hits a cap is REFUSED before the next external mutation — evidence is
never silently truncated and the only evidence of a possible mutation is
never evicted.
"""

from __future__ import annotations

import hashlib
import re
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

#: Maximum canonical resources the manifest policy may approve (see
#: ``kubernetes_manifest_policy.MAX_CANONICAL_RESOURCES`` — enforced there,
#: before any server-side dry run and before approval).
MAX_CANONICAL_RESOURCES = 32

#: Maximum DETAILED apply-attempt records per deployment run. The next
#: sandbox invocation is refused once this many attempts exist.
MAX_DETAILED_ATTEMPTS = 16

EVIDENCE_SCHEMA_VERSION = 1
EVIDENCE_KEY = "kubernetes_operation_evidence"
LEGACY_UNCERTAINTY_KEY = "legacy_uncertainty"

#: Attempt states.
HANDOFF_PENDING = "HANDOFF_PENDING"
RESULT_RECORDED = "RESULT_RECORDED"

#: Operations that hand an external mutation to the sandbox.
ATTEMPT_OPERATION_APPLY = "apply"

#: Evidence states for rollback gating / reporting.
STATE_NOT_APPLICABLE = "NOT_APPLICABLE"   # Kubernetes is not a declared component
STATE_NOT_ATTEMPTED = "NOT_ATTEMPTED"     # durable protocol record with zero handoffs
STATE_HANDOFF_PENDING = "HANDOFF_PENDING"
STATE_RESULT_RECORDED = "RESULT_RECORDED"
STATE_LEGACY_UNKNOWN = "LEGACY_UNKNOWN"

#: Rollback compensation classifications (P2.1: automatic Kubernetes undo
#: is NEVER authorized; BLOCKED is an operator-escalation reason).
COMPENSATION_NOT_REQUIRED = "NOT_REQUIRED"
COMPENSATION_BLOCKED = "BLOCKED"

#: In-flight states a pre-protocol (legacy) record may carry without any
#: trustworthy operation evidence — always classified LEGACY_UNKNOWN.
LEGACY_IN_FLIGHT_STATES = frozenset({"DEPLOYING", "HEALTH_CHECKING", "ROLLBACK_PENDING"})


class KubernetesAttemptCapacityRefused(RuntimeError):
    """A host-owned evidence capacity limit refused the next mutation.

    Deliberately distinct from lease loss: a capacity refusal is a
    preflight refusal, not an ownership loss, and must never be reported
    (or handled) as if the worker no longer owned its lease.
    """

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


class KubernetesEvidenceError(ValueError):
    """Malformed or unusable evidence input (fail closed)."""


def empty_evidence() -> Dict[str, Any]:
    """A schema-versioned, zero-attempt evidence record.

    Its presence is what makes ``NOT_ATTEMPTED`` PROVABLE for runs created
    under the new protocol. Legacy records (absent key) are never
    back-filled: a missing field must never be read as proof of no handoff.
    """
    return {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "may_have_mutated": False,
        "attempt_count": 0,
        "resources": [],
        "attempts": [],
    }


_ATTEMPT_ID = re.compile(r"^kat-[0-9a-f]{16}$")
_RESULT_STATUSES = frozenset({"PASS", "FAIL", "TIMEOUT", "CANCELLED"})


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _require_exact_version(value: Any, subject: str) -> None:
    if not _is_int(value) or value != EVIDENCE_SCHEMA_VERSION:
        raise KubernetesEvidenceError(
            f"{subject} must use exactly supported schema version "
            f"{EVIDENCE_SCHEMA_VERSION}")


def _validate_result(result: Any) -> None:
    if not isinstance(result, dict):
        raise KubernetesEvidenceError("a recorded attempt result must be an object")
    status = result.get("status")
    if not isinstance(status, str) or status not in _RESULT_STATUSES:
        raise KubernetesEvidenceError("a recorded attempt result has an invalid status")
    exit_code = result.get("exit_code")
    if not _is_int(exit_code) or exit_code < 0:
        raise KubernetesEvidenceError("a recorded attempt result has an invalid exit_code")
    for key in ("timed_out", "cancelled"):
        if not isinstance(result.get(key), bool):
            raise KubernetesEvidenceError(
                f"a recorded attempt result has a non-Boolean {key}")


def validate_evidence(evidence: Any) -> Dict[str, Any]:
    """Validate the complete v1 protocol record before it is interpreted.

    This is intentionally stricter than a truthiness check.  An unknown
    version, a counter/list disagreement, or an internally contradictory
    record is uncertainty, never evidence that no operation was handed off.
    """
    if not isinstance(evidence, dict):
        raise KubernetesEvidenceError("Kubernetes operation evidence must be an object")
    _require_exact_version(evidence.get("schema_version"), "evidence")
    if not isinstance(evidence.get("may_have_mutated"), bool):
        raise KubernetesEvidenceError("evidence may_have_mutated must be Boolean")
    if LEGACY_UNCERTAINTY_KEY in evidence and not isinstance(
            evidence[LEGACY_UNCERTAINTY_KEY], bool):
        raise KubernetesEvidenceError("evidence legacy_uncertainty must be Boolean")
    attempts = evidence.get("attempts")
    resources = evidence.get("resources")
    count = evidence.get("attempt_count")
    if not _is_int(count) or count < 0:
        raise KubernetesEvidenceError("evidence attempt_count must be a nonnegative integer")
    if not isinstance(attempts, list) or not isinstance(resources, list):
        raise KubernetesEvidenceError("evidence attempts and resources must be arrays")
    if count != len(attempts):
        raise KubernetesEvidenceError("evidence attempt_count does not match attempts")
    if len(attempts) > MAX_DETAILED_ATTEMPTS:
        raise KubernetesEvidenceError("evidence exceeds the detailed attempt limit")
    if len(resources) > MAX_CANONICAL_RESOURCES:
        raise KubernetesEvidenceError("evidence exceeds the canonical resource limit")

    ids = set()
    attempt_may_mutate = False
    for attempt in attempts:
        if not isinstance(attempt, dict):
            raise KubernetesEvidenceError("evidence contains a malformed attempt")
        attempt_id = attempt.get("attempt_id")
        if not isinstance(attempt_id, str) or not _ATTEMPT_ID.fullmatch(attempt_id) \
                or attempt_id in ids:
            raise KubernetesEvidenceError("evidence attempt IDs must be valid and unique")
        ids.add(attempt_id)
        if attempt.get("operation") != ATTEMPT_OPERATION_APPLY:
            raise KubernetesEvidenceError("evidence contains an unknown attempt operation")
        _require_exact_version(attempt.get("schema_version"), "attempt")
        if attempt.get("state") not in (HANDOFF_PENDING, RESULT_RECORDED):
            raise KubernetesEvidenceError("evidence contains an unknown attempt state")
        if not isinstance(attempt.get("may_have_mutated"), bool):
            raise KubernetesEvidenceError("attempt may_have_mutated must be Boolean")
        if attempt["may_have_mutated"]:
            attempt_may_mutate = True
        if attempt["state"] == HANDOFF_PENDING:
            if attempt.get("result") is not None or not attempt["may_have_mutated"]:
                raise KubernetesEvidenceError("a pending attempt contradicts mutation evidence")
        else:
            _validate_result(attempt.get("result"))

    resource_may_mutate = False
    keys = set()
    for summary in resources:
        if not isinstance(summary, dict):
            raise KubernetesEvidenceError("evidence contains a malformed resource summary")
        required = ("resource_key", "apiVersion", "kind", "namespace", "name",
                    "may_have_mutated", "last_attempt_id")
        if any(not isinstance(summary.get(key), str) or not summary[key] for key in required
               if key != "may_have_mutated") or not isinstance(
                   summary.get("may_have_mutated"), bool):
            raise KubernetesEvidenceError("resource summary identity is incomplete")
        expected_key = canonical_resource_key(summary, summary["namespace"])
        if summary["resource_key"] != expected_key or summary["resource_key"] in keys:
            raise KubernetesEvidenceError("resource summaries must have unique canonical identities")
        if summary["last_attempt_id"] not in ids:
            raise KubernetesEvidenceError("resource summary references an unknown attempt")
        keys.add(summary["resource_key"])
        resource_may_mutate = resource_may_mutate or summary["may_have_mutated"]

    if (attempt_may_mutate or resource_may_mutate) and not evidence["may_have_mutated"]:
        raise KubernetesEvidenceError("evidence contradicts a possible mutation")
    return evidence


def ensure_evidence(
    execution: Dict[str, Any], *, legacy_uncertainty: bool = False
) -> Dict[str, Any]:
    """Attach an empty evidence record ONLY when none exists.

    Never overwrites an existing record and never upgrades a legacy
    (schema-less) in-flight record into a protocol record.
    """
    evidence = execution.get(EVIDENCE_KEY)
    if evidence is not None:
        return validate_evidence(evidence)
    created = empty_evidence()
    if legacy_uncertainty:
        created[LEGACY_UNCERTAINTY_KEY] = True
    execution[EVIDENCE_KEY] = created
    return created


def get_evidence(execution: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The existing evidence record, or None for a legacy record."""
    evidence = (execution or {}).get(EVIDENCE_KEY)
    if evidence is None:
        return None
    return validate_evidence(evidence)


def canonical_resource_key(resource: Dict[str, str], namespace: str) -> str:
    """Canonical ``apiVersion/kind/namespace/name`` identity of one resource."""
    return "{apiVersion}/{kind}/{namespace}/{name}".format(
        apiVersion=str(resource.get("apiVersion", "")),
        kind=str(resource.get("kind", "")),
        namespace=namespace,
        name=str(resource.get("name", "")),
    )


def resource_set_identity(resources: List[Dict[str, str]], namespace: str) -> str:
    """Deterministic non-secret identity of the canonical resource set."""
    keys = sorted(canonical_resource_key(r, namespace) for r in resources)
    material = "|".join(keys)
    return "k8s-resource-set-v1:" + hashlib.sha256(material.encode()).hexdigest()


def _validated_handoff_context(context: Any) -> Dict[str, Any]:
    """Validate the runner-supplied handoff context (trusted metadata).

    The context is derived from the ALREADY VALIDATED manifest policy
    result, never from request fields. Required keys are checked; nothing
    here carries secret material (digests, kinds, names only).
    """
    if not isinstance(context, dict):
        raise KubernetesEvidenceError("the sandbox handoff context is malformed")
    required = (
        "operation", "schema_version", "manifest_sha256",
        "approved_identity_digest", "namespace", "resources",
    )
    missing = [key for key in required if not context.get(key)]
    if missing:
        raise KubernetesEvidenceError(
            "the sandbox handoff context is missing trusted metadata: "
            + ", ".join(missing))
    if context["operation"] != ATTEMPT_OPERATION_APPLY:
        raise KubernetesEvidenceError(
            f"operation {context['operation']!r} is not an evidenced mutation")
    _require_exact_version(context.get("schema_version"), "handoff context")
    resources = context["resources"]
    if not isinstance(resources, list) or not resources:
        raise KubernetesEvidenceError(
            "the handoff context carries no canonical resource set")
    if len(resources) > MAX_CANONICAL_RESOURCES:
        raise KubernetesAttemptCapacityRefused(
            "RESOURCE_CAP",
            f"the approved manifest carries {len(resources)} canonical "
            f"resources; the host-owned limit is {MAX_CANONICAL_RESOURCES}",
        )
    for resource in resources:
        if not isinstance(resource, dict) or not all(
                isinstance(resource.get(key), str) and resource[key]
                for key in ("apiVersion", "kind", "name")):
            raise KubernetesEvidenceError(
                "the handoff context carries a malformed canonical resource")
    return context


def record_attempt(
    evidence: Dict[str, Any],
    context: Dict[str, Any],
    *,
    timestamp: Optional[float] = None,
) -> Dict[str, Any]:
    """Record one HANDOFF_PENDING apply attempt (monotonic, bounded).

    Updates the non-evictable per-resource summaries (OR-only
    ``may_have_mutated``) and the run-scalar monotonic fact. Raises
    :class:`KubernetesAttemptCapacityRefused` BEFORE mutating anything when
    a host-owned bound is reached — the caller must refuse the next
    sandbox invocation.
    """
    context = _validated_handoff_context(context)
    validate_evidence(evidence)
    attempt_count = evidence["attempt_count"]
    if attempt_count >= MAX_DETAILED_ATTEMPTS:
        raise KubernetesAttemptCapacityRefused(
            "ATTEMPT_CAP",
            f"this run already carries {attempt_count} detailed "
            f"Kubernetes apply attempts; the host-owned limit is "
            f"{MAX_DETAILED_ATTEMPTS}",
        )

    namespace = str(context["namespace"])
    manifest_sha256 = str(context["manifest_sha256"])
    identity_digest = str(context["approved_identity_digest"])
    at = float(timestamp if timestamp is not None else time.time())
    attempt: Dict[str, Any] = {
        "attempt_id": f"kat-{uuid.uuid4().hex[:16]}",
        "operation": ATTEMPT_OPERATION_APPLY,
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "manifest_sha256": manifest_sha256,
        "approved_identity_digest": identity_digest,
        "namespace": namespace,
        "resource_set_identity": resource_set_identity(context["resources"], namespace),
        "handed_off_at": at,
        "state": HANDOFF_PENDING,
        "result": None,
        "may_have_mutated": True,
    }

    summaries = evidence["resources"]
    known_keys = {
        s["resource_key"]: s for s in summaries
    }
    incoming_keys = {
        canonical_resource_key(resource, namespace) for resource in context["resources"]
    }
    if len(set(known_keys).union(incoming_keys)) > MAX_CANONICAL_RESOURCES:
        raise KubernetesAttemptCapacityRefused(
            "RESOURCE_CAP",
            f"the run would exceed the host-owned limit of "
            f"{MAX_CANONICAL_RESOURCES} canonical resources",
        )
    for resource in context["resources"]:
        key = canonical_resource_key(resource, namespace)
        summary = known_keys.get(key)
        if summary is None:
            summary = {
                "resource_key": key,
                "apiVersion": str(resource.get("apiVersion", "")),
                "kind": str(resource.get("kind", "")),
                "namespace": namespace,
                "name": str(resource.get("name", "")),
                "may_have_mutated": True,
                "first_may_have_mutated_at": at,
                "last_attempt_id": attempt["attempt_id"],
            }
            known_keys[key] = summary
            summaries.append(summary)
        else:
            # Monotonic: a resource that may have mutated can never
            # return to "not mutated", no matter what a later retry does.
            summary["may_have_mutated"] = True
            summary["last_attempt_id"] = attempt["attempt_id"]

    evidence["attempts"].append(attempt)
    evidence["attempt_count"] = attempt_count + 1
    evidence["may_have_mutated"] = True
    return attempt


def record_attempt_result(
    evidence: Dict[str, Any],
    result_payload: Dict[str, Any],
    *,
    attempt_id: str,
    timestamp: Optional[float] = None,
) -> str:
    """Attach the received runner result to its exact pending attempt.

    Returns the attempt id, or None when no pending attempt exists (a
    pre-handoff refusal produced a result but never reached the sandbox —
    nothing to finalize). A FAIL/TIMEOUT/CANCELLED result still keeps
    ``may_have_mutated`` true: a failed command is not proof of a no-op.
    """
    validate_evidence(evidence)
    if not isinstance(attempt_id, str) or not _ATTEMPT_ID.fullmatch(attempt_id):
        raise KubernetesEvidenceError("attempt result is missing a valid attempt ID")
    payload = result_payload
    _validate_result(payload)
    pending = next((a for a in evidence["attempts"]
                    if a["attempt_id"] == attempt_id), None)
    if pending is None or pending["state"] != HANDOFF_PENDING:
        raise KubernetesEvidenceError(
            "attempt result does not match an outstanding handoff")
    pending["state"] = RESULT_RECORDED
    pending["result"] = {
        "status": payload["status"],
        "exit_code": payload["exit_code"],
        "timed_out": payload["timed_out"],
        "cancelled": payload["cancelled"],
    }
    pending["recorded_at"] = float(timestamp if timestamp is not None else time.time())
    # Raw stdout/stderr, kubeconfig and provider output are never copied
    # into the evidence record: the run's own ``kubernetes_apply`` payload
    # already carries the bounded, sanitized result.
    pending["may_have_mutated"] = True
    evidence["may_have_mutated"] = True
    return pending["attempt_id"]


def classify_compensation(
    *,
    execution: Dict[str, Any],
    state_value: str,
    kubernetes_declared: bool,
) -> Dict[str, Any]:
    """Classify what rollback may truthfully do about Kubernetes.

    Returns ``{"state": NOT_REQUIRED|BLOCKED, "evidence_state": ...,
    "may_have_mutated": bool|None, "reason": ...}``.

    P2.1 rule: any possibility of a mutation (or any inability to exclude
    one) BLOCKS automatic Kubernetes compensation — there is no authorized
    read/compare/conditional-write mechanism to prove current-resource
    ownership, so ``kubectl rollout undo`` is never invoked.

    Legacy rules (schema-less records — never read a missing Boolean as
    proof of NOT_ATTEMPTED):
    * an explicit durable PASS/FAIL/TIMEOUT/CANCELLED result that indicates
      cluster access is treated as potentially mutated;
    * an in-flight record without trustworthy evidence is LEGACY_UNKNOWN;
    * every other schema-less record is LEGACY_UNKNOWN (conservative).
    """
    try:
        evidence = get_evidence(execution)
    except KubernetesEvidenceError as exc:
        return {
            "state": COMPENSATION_BLOCKED, "evidence_state": STATE_LEGACY_UNKNOWN,
            "may_have_mutated": None,
            "reason": f"Kubernetes operation evidence is malformed: {exc}",
        }
    if not kubernetes_declared:
        if evidence is not None and (evidence["may_have_mutated"] or evidence["attempts"]
                                     or evidence["resources"]):
            return {
                "state": COMPENSATION_BLOCKED, "evidence_state": STATE_LEGACY_UNKNOWN,
                "may_have_mutated": None,
                "reason": "Kubernetes was declared absent but operation evidence exists",
            }
        legacy = (execution or {}).get("kubernetes_apply")
        if isinstance(legacy, dict) and legacy.get("cluster_access") is True:
            return {
                "state": COMPENSATION_BLOCKED, "evidence_state": STATE_LEGACY_UNKNOWN,
                "may_have_mutated": None,
                "reason": "Kubernetes was declared absent but legacy operation evidence exists",
            }
        return {
            "state": COMPENSATION_NOT_REQUIRED,
            "evidence_state": STATE_NOT_APPLICABLE,
            "may_have_mutated": False,
            "reason": "Kubernetes is not a declared component of this deployment.",
        }
    if evidence is not None:
        if evidence["may_have_mutated"] or evidence.get(LEGACY_UNCERTAINTY_KEY):
            attempts = evidence["attempts"]
            pending = any(
                isinstance(a, dict) and a.get("state") == HANDOFF_PENDING
                for a in attempts
            )
            return {
                "state": COMPENSATION_BLOCKED,
                "evidence_state": STATE_HANDOFF_PENDING if pending else STATE_RESULT_RECORDED,
                "may_have_mutated": True,
                "reason": (
                    "a sandbox apply handoff may have mutated Kubernetes and "
                    "conditional compensation is not implemented in this phase; "
                    "automatic rollback is refused and operator intervention is "
                    "required"),
            }
        return {
            "state": COMPENSATION_NOT_REQUIRED,
            "evidence_state": STATE_NOT_ATTEMPTED,
            "may_have_mutated": False,
            "reason": (
                "durable protocol evidence proves no sandbox apply handoff "
                "was ever made for this run"),
        }
    # Legacy (schema-less) record: absence of evidence is never proof of
    # no attempt.
    legacy = (execution or {}).get("kubernetes_apply")
    if isinstance(legacy, dict) and legacy.get("cluster_access") is True:
        status = str(legacy.get("status", ""))
        return {
            "state": COMPENSATION_BLOCKED,
            "evidence_state": STATE_LEGACY_UNKNOWN,
            "may_have_mutated": None,
            "reason": (
                f"a durable legacy Kubernetes result ({status or 'unknown'}) "
                "indicates cluster access; mutation cannot be excluded"),
        }
    if state_value in LEGACY_IN_FLIGHT_STATES:
        return {
            "state": COMPENSATION_BLOCKED,
            "evidence_state": STATE_LEGACY_UNKNOWN,
            "may_have_mutated": None,
            "reason": (
                "a legacy in-flight record carries no trustworthy Kubernetes "
                "operation evidence (LEGACY_UNKNOWN); mutation cannot be "
                "excluded"),
        }
    return {
        "state": COMPENSATION_BLOCKED,
        "evidence_state": STATE_LEGACY_UNKNOWN,
        "may_have_mutated": None,
        "reason": (
            "a legacy record predates the operation-evidence protocol "
            "(LEGACY_UNKNOWN); mutation cannot be excluded"),
    }


def evidence_attempt_ids(evidence: Optional[Dict[str, Any]]) -> List[str]:
    """Bounded reference list of recorded attempt ids (for rollback metadata)."""
    if not isinstance(evidence, dict):
        return []
    ids: List[str] = []
    for attempt in (evidence.get("attempts") or []):
        if isinstance(attempt, dict) and attempt.get("attempt_id"):
            ids.append(str(attempt["attempt_id"]))
    return ids[:MAX_DETAILED_ATTEMPTS]
