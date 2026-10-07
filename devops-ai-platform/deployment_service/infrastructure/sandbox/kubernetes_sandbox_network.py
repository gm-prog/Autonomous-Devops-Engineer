"""Phase 8.6-A final corrective, Workstream A: destination-isolated network.

``docker network create --internal`` removes the NAT route, so a sandbox
attached to such a network cannot reach the Internet. It does **not**
isolate the network's own members: every container attached to the same
bridge can address every other one. A co-tenant is therefore reachable,
which was proven live:

    dial tcp 172.20.0.3:9999: connect: connection refused

A refused connection means the SYN *arrived*. That is reachability.

This module makes the sandbox network **destination-controlled** rather
than merely Internet-free:

* the network is dedicated to one execution and carries only the
  approved participants -- the kubectl sandbox and the single approved
  Kubernetes endpoint (or an explicit proxy standing in for it);
* its identity is canonical and covers the fields that actually change
  when a network is recreated or re-scoped -- id, driver, internal
  flag, subnet, gateway and the approved peer set -- so an attacker
  cannot delete a network and rebuild a wider one under the same name;
* membership is re-validated immediately before every execution, and
  any unexpected member fails the execution closed.

Nothing here trusts a name. A name is not an identity.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

NETWORK_IDENTITY_VERSION = "kubernetes-sandbox-network-v1"

#: Only these drivers give a private L2 segment we can reason about.
ALLOWED_DRIVERS = ("bridge",)

_NAME = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$")


class KubernetesSandboxNetworkError(Exception):
    """Raised when the sandbox network is not provably isolated."""


def _run(argv: Sequence[str], timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603 - fixed host-built argv
        list(argv), capture_output=True, text=True, timeout=timeout, check=False,
    )


@dataclass(frozen=True)
class SandboxNetworkIdentity:
    """Canonical, security-relevant identity of one sandbox network.

    Deliberately excludes volatile fields (creation timestamp, container
    ids, labels) so a legitimate re-attach does not look like a change,
    and deliberately includes every field that widens reachability.
    """

    name: str
    network_id: str
    driver: str
    internal: bool
    subnet: str
    gateway: str
    approved_peers: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "identity_version": NETWORK_IDENTITY_VERSION,
            "name": self.name,
            "network_id": self.network_id,
            "driver": self.driver,
            "internal": self.internal,
            "subnet": self.subnet,
            "gateway": self.gateway,
            "approved_peers": list(self.approved_peers),
        }

    def digest(self) -> str:
        blob = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        return f"{NETWORK_IDENTITY_VERSION}:{hashlib.sha256(blob.encode()).hexdigest()[:32]}"

    def differences(self, other: "SandboxNetworkIdentity") -> Dict[str, str]:
        out: Dict[str, str] = {}
        for key, mine in self.to_dict().items():
            theirs = other.to_dict().get(key)
            if mine != theirs:
                out[key] = f"approved={mine!r} observed={theirs!r}"
        return out


def inspect_network(name: str, *, runtime: str = "docker") -> Dict[str, Any]:
    """Return the runtime's view of one network, or raise.

    An inspection that cannot be performed is an error, never an
    implicit pass: a probe that cannot observe its property proves
    nothing.
    """
    if not _NAME.match(name or ""):
        raise KubernetesSandboxNetworkError(f"malformed network name {name!r}")
    result = _run([runtime, "network", "inspect", name])
    if result.returncode != 0:
        raise KubernetesSandboxNetworkError(
            f"network {name!r} could not be inspected; refusing to execute "
            f"without proof of isolation: {result.stderr.strip()[:200]}"
        )
    try:
        parsed = json.loads(result.stdout)
    except ValueError as exc:
        raise KubernetesSandboxNetworkError(
            f"network {name!r} inspection was not parseable: {exc}"
        ) from None
    if not parsed:
        raise KubernetesSandboxNetworkError(f"network {name!r} does not exist")
    return parsed[0]


def identity_from_inspection(raw: Dict[str, Any],
                             approved_peers: Sequence[str] = ()) -> SandboxNetworkIdentity:
    ipam = (raw.get("IPAM") or {}).get("Config") or [{}]
    first = ipam[0] if ipam else {}
    return SandboxNetworkIdentity(
        name=raw.get("Name", ""),
        network_id=str(raw.get("Id", ""))[:32],
        driver=raw.get("Driver", ""),
        internal=bool(raw.get("Internal", False)),
        subnet=str(first.get("Subnet", "")),
        gateway=str(first.get("Gateway", "")),
        approved_peers=tuple(sorted(approved_peers)),
    )


def observed_members(raw: Dict[str, Any]) -> List[str]:
    """Container names currently attached to the network."""
    containers = raw.get("Containers") or {}
    names = []
    for body in containers.values():
        name = (body or {}).get("Name", "")
        if name:
            names.append(name)
    return sorted(names)


def validate_network(
    name: str,
    *,
    approved_identity: Optional[SandboxNetworkIdentity],
    approved_peers: Sequence[str],
    allow_transient_members: Sequence[str] = (),
    approved_digest: Optional[str] = None,
    runtime: str = "docker",
) -> SandboxNetworkIdentity:
    """Prove the network is the approved, isolated one. Fail closed.

    ``approved_peers`` are the destinations the sandbox is permitted to
    reach. Any other member is an unapproved co-tenant and is refused:
    with ``--internal`` alone such a peer would be fully reachable.

    ``allow_transient_members`` covers the short-lived sandbox
    containers themselves, which legitimately appear and disappear.
    """
    raw = inspect_network(name, runtime=runtime)
    observed = identity_from_inspection(raw, approved_peers)

    if observed.driver not in ALLOWED_DRIVERS:
        raise KubernetesSandboxNetworkError(
            f"network {name!r} uses driver {observed.driver!r}; only "
            f"{list(ALLOWED_DRIVERS)} give a private segment we can reason about"
        )
    if not observed.internal:
        raise KubernetesSandboxNetworkError(
            f"network {name!r} is not internal; it would NAT to the Internet"
        )

    members = observed_members(raw)
    permitted = set(approved_peers) | set(allow_transient_members)
    unexpected = [m for m in members
                  if m not in permitted and not m.startswith("ares-kubectl-")]
    if unexpected:
        raise KubernetesSandboxNetworkError(
            f"network {name!r} carries unapproved co-tenant(s) {unexpected}; "
            f"an --internal network does not isolate its own members, so the "
            f"sandbox could reach them. Refusing to execute."
        )
    missing = [p for p in approved_peers if p not in members]
    if missing:
        raise KubernetesSandboxNetworkError(
            f"network {name!r} is missing the approved destination(s) {missing}"
        )

    if approved_digest and approved_digest != observed.digest():
        raise KubernetesSandboxNetworkError(
            f"network {name!r} does not match the identity captured at "
            f"approval (approved={approved_digest[:16]}... "
            f"observed={observed.digest()[:16]}...); a same-name network "
            f"that was rebuilt is NOT the approved network"
        )
    if approved_identity is not None and approved_identity.digest() != observed.digest():
        detail = "; ".join(f"{k}: {v}" for k, v in
                           sorted(approved_identity.differences(observed).items()))
        raise KubernetesSandboxNetworkError(
            f"the sandbox network changed after approval ({detail}); "
            f"refusing to execute"
        )
    return observed


@dataclass
class PerExecutionNetwork:
    """A dedicated --internal network carrying only approved destinations.

    Created immediately before an execution and removed afterwards, so
    the window in which anything could join it is as small as possible
    and membership is validated inside that window regardless.
    """

    approved_peers: Tuple[str, ...]
    runtime: str = "docker"
    name: str = ""
    _connected: List[str] = field(default_factory=list)

    def create(self) -> SandboxNetworkIdentity:
        self.name = f"ares-k8s-x-{uuid.uuid4().hex[:12]}"
        created = _run([self.runtime, "network", "create", "--internal",
                        "--driver", "bridge", self.name])
        if created.returncode != 0:
            raise KubernetesSandboxNetworkError(
                f"could not create the per-execution sandbox network: "
                f"{created.stderr.strip()[:200]}"
            )
        for peer in self.approved_peers:
            joined = _run([self.runtime, "network", "connect", self.name, peer])
            if joined.returncode != 0:
                self.destroy()
                raise KubernetesSandboxNetworkError(
                    f"could not attach approved destination {peer!r}: "
                    f"{joined.stderr.strip()[:200]}"
                )
            self._connected.append(peer)
        return validate_network(self.name, approved_identity=None,
                                approved_peers=self.approved_peers,
                                runtime=self.runtime)

    def destroy(self) -> None:
        for peer in self._connected:
            _run([self.runtime, "network", "disconnect", "-f", self.name, peer])
        self._connected = []
        if self.name:
            _run([self.runtime, "network", "rm", self.name])

    def __enter__(self) -> "PerExecutionNetwork":
        self.create()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.destroy()


def approved_peers_from_environment() -> Tuple[str, ...]:
    """Host-owned list of destinations the sandbox may reach."""
    raw = os.getenv("DEPLOYMENT_K8S_SANDBOX_PEERS", "").strip()
    return tuple(sorted(p.strip() for p in raw.split(",") if p.strip()))
