"""Phase 8.6-A — least-privilege RBAC profile for the deployment identity.

The subject ARES authenticates as must be able to do exactly what the
four permitted operations need inside one namespace, and nothing else.
This module is the single source of that profile: it generates the
Role/RoleBinding applied to the cluster and exposes the same rules to
the tests, so the manifest and the assertions cannot drift apart.

Starting point is DENY: the rule set below is built by listing the API
calls each operation makes, not by trimming an admin role.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

import yaml

#: Verbs each operation actually requires.
#:
#:   server-side apply  -> get, patch (SSA is a PATCH), create
#:   apply              -> get, patch, create
#:   rollout status     -> get, list, watch on deployments + replicasets
#:   rollout undo       -> get, list, patch, update on deployments,
#:                         get/list on replicasets (to find the revision)
#:
#: Pods are read-only: rollout status surfaces pod-level failures, and
#: the health check reads pod status. Nothing writes pods directly.
REQUIRED_RULES: Tuple[Dict[str, Any], ...] = (
    {
        "apiGroups": ["apps"],
        "resources": ["deployments"],
        "verbs": ["get", "list", "watch", "create", "update", "patch"],
    },
    {
        "apiGroups": ["apps"],
        "resources": ["replicasets"],
        "verbs": ["get", "list", "watch"],
    },
    {
        "apiGroups": [""],
        "resources": ["pods"],
        "verbs": ["get", "list", "watch"],
    },
    {
        "apiGroups": [""],
        "resources": ["services", "configmaps"],
        "verbs": ["get", "list", "watch", "create", "update", "patch"],
    },
)

#: Verbs that must never appear, whatever else changes.
FORBIDDEN_VERBS = frozenset({
    "*", "delete", "deletecollection", "escalate", "bind", "impersonate",
    "proxy",
})

#: Resources that must never appear in the profile. Secret reads are
#: excluded because no permitted operation needs one; if that ever
#: changes it must be proven, not assumed.
FORBIDDEN_RESOURCES = frozenset({
    "*", "secrets", "serviceaccounts", "roles", "rolebindings",
    "clusterroles", "clusterrolebindings", "nodes", "namespaces",
    "persistentvolumes", "pods/exec", "pods/attach", "pods/portforward",
})

ROLE_NAME = "ares-deployer"
BINDING_NAME = "ares-deployer"


class RbacProfileError(ValueError):
    """Raised when a profile violates the least-privilege contract."""


def validate_rules(rules: Tuple[Dict[str, Any], ...]) -> None:
    """Fail closed on any wildcard, escalation verb or forbidden resource."""
    if not rules:
        raise RbacProfileError("an empty rule set proves nothing; declare the rules")
    for index, rule in enumerate(rules):
        where = f"rule {index}"
        for group in rule.get("apiGroups", []):
            if group == "*":
                raise RbacProfileError(f"{where} uses a wildcard apiGroup")
        for resource in rule.get("resources", []):
            if resource in FORBIDDEN_RESOURCES:
                raise RbacProfileError(f"{where} grants {resource!r}, which is forbidden")
        for verb in rule.get("verbs", []):
            if verb in FORBIDDEN_VERBS:
                raise RbacProfileError(f"{where} grants verb {verb!r}, which is forbidden")
        if not rule.get("verbs"):
            raise RbacProfileError(f"{where} grants no verbs")


def build_profile(namespace: str, service_account: str) -> List[Dict[str, Any]]:
    """Return the namespaced Role and RoleBinding as plain dicts.

    Both objects are namespaced. There is deliberately no ClusterRole
    and no ClusterRoleBinding: a cluster-scoped grant would make the
    namespace boundary cosmetic.
    """
    validate_rules(REQUIRED_RULES)
    role = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": {"name": ROLE_NAME, "namespace": namespace},
        "rules": [dict(rule) for rule in REQUIRED_RULES],
    }
    binding = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "RoleBinding",
        "metadata": {"name": BINDING_NAME, "namespace": namespace},
        "roleRef": {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "Role",
            "name": ROLE_NAME,
        },
        "subjects": [{
            "kind": "ServiceAccount",
            "name": service_account,
            "namespace": namespace,
        }],
    }
    return [role, binding]


def render(namespace: str, service_account: str) -> str:
    return yaml.safe_dump_all(
        build_profile(namespace, service_account),
        sort_keys=True,
        default_flow_style=False,
        explicit_start=True,
    )


#: Authorization checks the live E2E must run with `kubectl auth can-i`
#: as the deployment subject. Each entry is (verb, resource, namespace
#: or None for cluster scope, expected_allowed).
#:
#: These are *real* authorization queries against the API server's RBAC
#: evaluator, not inspection of the YAML above. A profile can look
#: correct and still be bound incorrectly.
AUTHORIZATION_EXPECTATIONS: Tuple[Tuple[str, str, bool], ...] = (
    # --- must be allowed, in the deployment namespace ---------------
    ("get", "deployments.apps", True),
    ("patch", "deployments.apps", True),
    ("create", "deployments.apps", True),
    ("list", "replicasets.apps", True),
    ("get", "pods", True),
    # --- must be denied, in the SAME namespace ----------------------
    ("delete", "deployments.apps", False),
    ("get", "secrets", False),
    ("create", "secrets", False),
    ("create", "serviceaccounts", False),
    ("create", "roles.rbac.authorization.k8s.io", False),
    ("create", "rolebindings.rbac.authorization.k8s.io", False),
    ("create", "pods/exec", False),
)

#: Cluster-scoped queries that must all be denied.
CLUSTER_SCOPED_DENIALS: Tuple[Tuple[str, str], ...] = (
    ("list", "namespaces"),
    ("create", "namespaces"),
    ("list", "nodes"),
    ("create", "clusterroles.rbac.authorization.k8s.io"),
    ("create", "clusterrolebindings.rbac.authorization.k8s.io"),
    ("list", "secrets"),
    ("get", "persistentvolumes"),
)
