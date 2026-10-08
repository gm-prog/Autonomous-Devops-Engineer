"""Phase 8.7-B.2 — the trusted traffic mutation package.

The write side of the traffic boundary lives in its own package, and that
separation is load-bearing rather than cosmetic:

* Phase 8.7-B.1's ``incident_service/infrastructure/traffic`` package is
  provably read-only — its tests assert that the *only* process-spawning
  module in that directory is the read client and that no write verb
  appears outside the read policy's deny-list. Keeping the write path here
  means those guarantees stay literally true instead of being relaxed to
  make room for a mutation.
* Everything that can change cluster state is therefore in one directory
  with one entry point:
  :class:`~incident_service.infrastructure.traffic_mutation.trusted_mutation_provider.TrustedTrafficMutationProvider`
  (the port implementation) over
  :class:`~incident_service.infrastructure.traffic_mutation.kubernetes_mutation_client.KubernetesMutationClient`
  (the one closed write client).

Both modules take their Kubernetes identifier validation from the B.1 read
client rather than re-implementing it: one interpretation of what a valid
cluster name, context or namespace is, used by both sides of the boundary.
"""

from incident_service.infrastructure.traffic_mutation.kubernetes_mutation_client import (  # noqa: E501
    ATTEMPT_ACCEPTED,
    ATTEMPT_REJECTED,
    ATTEMPT_UNKNOWN,
    BackendWeightChange,
    KubernetesMutationClient,
    KubernetesMutationPolicyViolation,
    MutationAttempt,
    MutationOperation,
    MutationWriteError,
    TrafficWriteConfig,
    WeightMutation,
    build_mutation_argv,
    build_weight_patch,
    classify_attempt,
)
from incident_service.infrastructure.traffic_mutation.trusted_mutation_provider import (  # noqa: E501
    InMemoryMutationAttemptRegistry,
    MutationClaimConflict,
    TrustedTrafficMutationProvider,
    evidence_to_json,
    percentage_from_weights,
    percentage_to_weights,
)

__all__ = [
    "ATTEMPT_ACCEPTED",
    "ATTEMPT_REJECTED",
    "ATTEMPT_UNKNOWN",
    "BackendWeightChange",
    "InMemoryMutationAttemptRegistry",
    "KubernetesMutationClient",
    "KubernetesMutationPolicyViolation",
    "MutationAttempt",
    "MutationClaimConflict",
    "MutationOperation",
    "MutationWriteError",
    "TrafficWriteConfig",
    "TrustedTrafficMutationProvider",
    "WeightMutation",
    "build_mutation_argv",
    "build_weight_patch",
    "classify_attempt",
    "evidence_to_json",
    "percentage_from_weights",
    "percentage_to_weights",
]
