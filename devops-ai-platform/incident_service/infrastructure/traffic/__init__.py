"""Phase 8.7-B.1 — read-only Kubernetes traffic observation.

Two modules, one responsibility each:

* :mod:`kubernetes_read_client` — the closed, read-only Kubernetes
  operation set and the client that executes it;
* :mod:`gateway_api_observer` — the provider that turns those reads into
  ``ObservedTrafficState`` through the existing provider-neutral
  ``TrafficControllerPort``.

Nothing in this package can mutate a Kubernetes resource: the client
exposes reads only, and the provider's ``plan()`` performs no cluster
access at all.
"""

from incident_service.infrastructure.traffic.gateway_api_observer import (
    OBSERVATION_SOURCE,
    PROVIDER_NAME,
    KubernetesTrafficObserver,
    TrafficObservation,
)
from incident_service.infrastructure.traffic.kubernetes_read_client import (
    KubernetesReadError,
    KubectlReadClient,
    ReadOperation,
    TrafficReadConfig,
)

__all__ = [
    "KubernetesReadError",
    "KubernetesTrafficObserver",
    "KubectlReadClient",
    "OBSERVATION_SOURCE",
    "PROVIDER_NAME",
    "ReadOperation",
    "TrafficObservation",
    "TrafficReadConfig",
]
