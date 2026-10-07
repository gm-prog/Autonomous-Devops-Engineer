#!/usr/bin/env python3
"""Prove the Kubernetes trust-boundary tests actually bite.

Phase 8.6-A, §73.

Same contract as the Terraform probe harness: a green security suite may
be green because the controls work, or green because nothing checks
them. Each probe deliberately weakens one control on a throwaway copy of
``devops-ai-platform`` and asserts the suite notices. The working tree is
never mutated.

Usage::

    python scripts/mutation_probe_kubernetes_boundary.py
    python scripts/mutation_probe_kubernetes_boundary.py --list
    python scripts/mutation_probe_kubernetes_boundary.py -k kubeconfig

Exit code 0 only if every probe was caught.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Sequence

PLATFORM_ROOT = Path(__file__).resolve().parent.parent

MANIFEST = "deployment_service/application/services/kubernetes_manifest_policy.py"
KUBECONFIG = "deployment_service/application/services/kubeconfig_policy.py"
SANDBOX = "deployment_service/application/services/kubectl_sandbox.py"
RUNNER = "deployment_service/application/services/kubectl_runner.py"
POLICY = "deployment_service/application/services/kubernetes_manifest_policy.py"
IDENTITY = "deployment_service/application/services/kubernetes_execution_identity.py"
ADAPTER = "deployment_service/infrastructure/sandbox/container_kubectl_sandbox.py"

BOUNDARY_TESTS = "deployment_service/tests/test_kubernetes_trust_boundary.py"


class MutationNotApplied(RuntimeError):
    """The mutation's anchor text was not found -- the probe is stale."""


def replace(path: str, old: str, new: str, count: int = 1) -> Callable[[Path], None]:
    def apply(root: Path) -> None:
        target = root / path
        text = target.read_text(encoding="utf-8")
        found = text.count(old)
        if found != count:
            raise MutationNotApplied(
                f"{path}: expected {count} occurrence(s) of {old[:60]!r}, "
                f"found {found}. The implementation moved; update the probe "
                f"rather than deleting it."
            )
        target.write_text(text.replace(old, new, count), encoding="utf-8")

    return apply


def chain(*mutations: Callable[[Path], None]) -> Callable[[Path], None]:
    def apply(root: Path) -> None:
        for mutation in mutations:
            mutation(root)

    return apply


@dataclass
class Probe:
    name: str
    description: str
    mutate: Callable[[Path], None]
    tests: Sequence[str] = field(default_factory=lambda: [BOUNDARY_TESTS])
    redundant_layer: bool = False


PROBES: list[Probe] = [
    # ---- manifest policy -------------------------------------------
    Probe(
        "allow-cluster-scoped-kinds",
        "empty the hard-deny list so ClusterRole becomes applyable",
        replace(MANIFEST, "HARD_DENIED_KINDS: frozenset = frozenset({",
                "HARD_DENIED_KINDS: frozenset = frozenset({} or {"),
        redundant_layer=True,
    ),
    Probe(
        "allow-cluster-scoped-kinds-combined",
        "strip BOTH kind layers: the hard-deny list and the allowlist",
        chain(
            replace(MANIFEST, "HARD_DENIED_KINDS: frozenset = frozenset({",
                    "HARD_DENIED_KINDS: frozenset = frozenset({} or {"),
            replace(MANIFEST, "if (api_version, kind) not in self.allowed_resources:",
                    "if False:"),
        ),
    ),
    Probe(
        "allow-any-kind",
        "turn the apiVersion/kind allowlist into allow-all",
        replace(MANIFEST,
                "if (api_version, kind) not in self.allowed_resources:",
                "if False:"),
    ),
    Probe(
        "ignore-declared-namespace",
        "stop rejecting a manifest that declares a foreign namespace",
        replace(MANIFEST,
                "if not isinstance(declared_ns, str) or declared_ns.strip() != self.namespace:",
                "if False:"),
    ),
    Probe(
        "allow-host-namespaces",
        "stop rejecting hostNetwork/hostPID/hostIPC",
        replace(MANIFEST, 'for host_field in ("hostNetwork", "hostPID", "hostIPC"):',
                'for host_field in ():'),
    ),
    Probe(
        "allow-privileged-containers",
        "stop rejecting privileged: true",
        replace(MANIFEST, 'if sc.get("privileged") is True:', "if False:"),
    ),
    Probe(
        "allow-privilege-escalation",
        "stop requiring allowPrivilegeEscalation: false",
        replace(MANIFEST, 'if sc.get("allowPrivilegeEscalation") is not False:',
                "if False:"),
    ),
    Probe(
        "allow-added-capabilities",
        "permit capabilities.add",
        replace(MANIFEST, "if added:", "if False:"),
    ),
    Probe(
        "allow-hostpath-volumes",
        "treat every volume type as acceptable",
        replace(MANIFEST, "elif source not in ALLOWED_VOLUME_TYPES:", "elif False:"),
        redundant_layer=True,
    ),
    Probe(
        "allow-every-volume-type-combined",
        "strip BOTH volume layers: deny-list and allow-list",
        chain(
            replace(MANIFEST, "if source in DENIED_VOLUME_TYPES:", "if False:"),
            replace(MANIFEST, "elif source not in ALLOWED_VOLUME_TYPES:", "elif False:"),
        ),
    ),
    Probe(
        "allow-arbitrary-service-account",
        "let a generated manifest choose its own ServiceAccount",
        replace(MANIFEST,
                'declared_sa = pod_spec.get("serviceAccountName") or pod_spec.get("serviceAccount")',
                "declared_sa = None"),
    ),
    Probe(
        "allow-unbounded-resources",
        "stop requiring cpu/memory requests and limits",
        replace(MANIFEST, "if self.require_resource_limits:", "if False:"),
    ),
    Probe(
        "allow-nodeport-services",
        "permit NodePort and LoadBalancer services",
        replace(MANIFEST, 'ALLOWED_SERVICE_TYPES: frozenset = frozenset({"ClusterIP"})',
                'ALLOWED_SERVICE_TYPES: frozenset = frozenset('
                '{"ClusterIP", "NodePort", "LoadBalancer"})'),
    ),
    Probe(
        "silently-rewrite-instead-of-reject",
        "downgrade a policy error to a warning so the manifest is accepted",
        replace(MANIFEST,
                '                status="FAIL", errors=errors, warnings=warnings,',
                '                status="PASS", errors=[], warnings=warnings,'),
    ),
    # ---- kubeconfig --------------------------------------------------
    Probe(
        "allow-exec-credential-plugin",
        "stop rejecting kubeconfig exec plugins",
        replace(KUBECONFIG, '    "exec",            # arbitrary external binary execution\n', ""),
        redundant_layer=True,
    ),
    Probe(
        "allow-exec-credential-plugin-combined",
        "strip BOTH kubeconfig layers: the deny list and the unknown-key check",
        chain(
            replace(KUBECONFIG, '    "exec",            # arbitrary external binary execution\n', ""),
            replace(KUBECONFIG, "if unknown:", "if False:"),
        ),
    ),
    Probe(
        "allow-proxy-url",
        "permit proxy-url so API traffic can be redirected",
        replace(KUBECONFIG, '    "proxy-url",\n', ""),
    ),
    Probe(
        "allow-insecure-tls",
        "permit insecure-skip-tls-verify",
        replace(KUBECONFIG, '    "insecure-skip-tls-verify",\n', ""),
    ),
    Probe(
        "allow-plain-http-endpoint",
        "accept an http:// API endpoint",
        replace(KUBECONFIG, 'if parsed.scheme != "https":', "if False:"),
    ),
    Probe(
        "forward-the-whole-kubeconfig",
        "pass the operator kubeconfig through instead of rebuilding it",
        replace(KUBECONFIG,
                "        content=yaml.safe_dump(rebuilt, sort_keys=True, default_flow_style=False),",
                "        content=raw_kubeconfig,"),
    ),
    # ---- sandbox runtime ---------------------------------------------
    Probe(
        "allow-host-networking",
        "permit --network host",
        replace(SANDBOX,
                'FORBIDDEN_NETWORK_MODES = frozenset({"host", "none", "container", "bridge", ""})',
                'FORBIDDEN_NETWORK_MODES = frozenset({"none", ""})'),
    ),
    Probe(
        "writable-rootfs",
        "drop --read-only from the container argv",
        replace(SANDBOX, '        "--read-only",\n', ""),
    ),
    Probe(
        "keep-capabilities",
        "stop dropping Linux capabilities in the sandbox",
        replace(SANDBOX, '        "--cap-drop", "ALL",\n', ""),
    ),
    Probe(
        "allow-new-privileges",
        "remove no-new-privileges",
        replace(SANDBOX, '        "--security-opt", "no-new-privileges:true",\n', ""),
    ),
    Probe(
        "run-sandbox-as-root",
        "accept uid 0 for the kubectl container",
        replace(SANDBOX, "if uid <= 0 or gid <= 0:", "if False:"),
    ),
    Probe(
        "unpinned-image",
        "accept a mutable image tag instead of a digest",
        replace(SANDBOX, "if not _DIGEST_PINNED.match(self.image or \"\"):", "if False:"),
    ),
    Probe(
        "allow-image-pull",
        "remove --pull never so the runtime may fetch a new image",
        replace(SANDBOX, '        "--pull", "never",\n', ""),
    ),
    Probe(
        "writable-mounts",
        "mount the manifest and kubeconfig read-write",
        chain(
            replace(SANDBOX, f'"-v", f"{{manifest_host_path}}:{{MANIFEST_PATH}}:ro"',
                    f'"-v", f"{{manifest_host_path}}:{{MANIFEST_PATH}}:rw"'),
            replace(SANDBOX, f'"-v", f"{{kubeconfig_host_path}}:{{KUBECONFIG_PATH}}:ro"',
                    f'"-v", f"{{kubeconfig_host_path}}:{{KUBECONFIG_PATH}}:rw"'),
        ),
    ),
    Probe(
        "inherit-proxy-environment",
        "forward host proxy variables into the kubectl process",
        replace(SANDBOX, '        "KUBERC": KUBERC_PATH,\n    }',
                '        "KUBERC": KUBERC_PATH,\n'
                '        "HTTPS_PROXY": os.getenv("HTTPS_PROXY", ""),\n'
                '        "HTTP_PROXY": os.getenv("HTTP_PROXY", ""),\n    }'),
    ),
    Probe(
        "mount-the-docker-socket",
        "give the sandbox the Docker socket",
        replace(SANDBOX, '        "-w", WORKSPACE_DIR,',
                '        "-v", "/var/run/docker.sock:/var/run/docker.sock",\n'
                '        "-w", WORKSPACE_DIR,'),
    ),
    # ---- command policy ----------------------------------------------
    Probe(
        "client-side-dry-run",
        "downgrade the server-side dry run to a client dry run",
        replace(SANDBOX,
                '            "--dry-run=server",\n            "--validate=strict",',
                '            "--dry-run=client",\n            "--validate=false",'),
    ),
    Probe(
        "allow-forbidden-subcommands",
        "open kubectl exec/cp/port-forward through the step validator",
        replace(SANDBOX, "if self.argv[1] in FORBIDDEN_SUBCOMMANDS:", "if False:"),
    ),
    Probe(
        "allow-arbitrary-manifest-path",
        "let -f reference any file instead of the approved manifest",
        replace(SANDBOX, "if index + 1 >= len(self.argv) or self.argv[index + 1] != MANIFEST_PATH:",
                "if False:"),
    ),
    Probe(
        "unvalidated-rollout-target",
        "accept any string as the rollout target name",
        replace(SANDBOX,
                "if not isinstance(deployment_name, str) or not _DNS_1123.match(deployment_name):",
                "if False:"),
    ),
    # ---- runner ------------------------------------------------------
    Probe(
        "allow-namespace-switch",
        "let a caller pick the execution namespace again",
        replace(RUNNER, "if namespace is not None and namespace != owned:", "if False:"),
    ),
    Probe(
        "skip-manifest-policy",
        "apply without evaluating the manifest policy",
        replace(RUNNER, "if not result.passed:", "if False:"),
    ),
    Probe(
        "execute-the-raw-manifest",
        "send the untrusted manifest instead of the approved canonical form",
        replace(RUNNER, "manifest_yaml=approved.canonical_yaml,\n"
                        "            extra={\n"
                        '                "manifest_sha256": approved.manifest_sha256,\n'
                        '                "manifest_policy_identity": approved.policy_identity,\n'
                        '                "applied_resources": approved.resources,',
                "manifest_yaml=Path(manifest_path).read_text(encoding=\"utf-8\"),\n"
                "            extra={\n"
                '                "manifest_sha256": approved.manifest_sha256,\n'
                '                "manifest_policy_identity": approved.policy_identity,\n'
                '                "applied_resources": approved.resources,'),
    ),
    Probe(
        "skip-kubernetes-whenever-convenient",
        "treat every deployment as having no Kubernetes component",
        replace("deployment_service/application/services/deployment_engine.py",
                'return bool(str(payload.get("k8s_yaml", "") or "").strip())',
                "return False"),
    ),
    Probe(
        "copy-the-host-environment",
        "hand the whole host environment to the container runtime",
        replace(ADAPTER, '        env = {\n            "PATH": "/usr/local/bin:/usr/bin:/bin",',
                '        env = os.environ.copy()\n        env |= {\n'
                '            "PATH": "/usr/local/bin:/usr/bin:/bin",'),
    ),

    # -----------------------------------------------------------------
    # Phase 8.6-A corrective. Workstream B: cluster identity binding.
    # -----------------------------------------------------------------
    Probe(
        "accept-any-execution-target",
        "stop comparing the approved and observed execution identity",
        replace(IDENTITY, "if approved.digest() != observed.digest():", "if False:"),
    ),
    Probe(
        "allow-unbound-mutation",
        "let a mutation run with no approved identity at all",
        replace(IDENTITY, "    if approved is None:", "    if False:"),
    ),
    Probe(
        "skip-binding-for-mutations",
        "never verify the binding on APPLY / ROLLOUT_UNDO",
        replace(RUNNER, "if operation in self.MUTATING_OPERATIONS:", "if False:"),
    ),
    Probe(
        "empty-mutating-operation-set",
        "declare that no operation mutates the cluster",
        replace(RUNNER, "MUTATING_OPERATIONS = (KubectlOperation.APPLY, "
                        "KubectlOperation.ROLLOUT_UNDO)",
                        "MUTATING_OPERATIONS = ()"),
    ),
    Probe(
        "unpin-the-api-server",
        "stop constraining the kubeconfig to the host-owned endpoint",
        replace(RUNNER, "expected_server=expected_api_server(),", "expected_server=None,"),
    ),
    Probe(
        "unpin-the-ca-fingerprint",
        "accept any cluster CA even when a fingerprint is pinned",
        replace(RUNNER, "if pinned_ca and sanitized.cluster_identity."
                        "ca_fingerprint_sha256 != pinned_ca:", "if False:"),
    ),
    Probe(
        "verify-after-the-sandbox",
        "move the binding check so the sandbox is called first",
        replace(RUNNER, "            verify_binding(approved_identity, observed_identity)\n"
                        "            elif approved_identity is not None:",
                        "            pass\n"
                        "            elif approved_identity is not None:"),
    ),
    # -----------------------------------------------------------------
    # Workstream C: Secret / PVC / ConfigMap reference escalation.
    # -----------------------------------------------------------------
    Probe(
        "allow-any-named-reference",
        "treat every Secret/PVC/ConfigMap reference as permitted",
        replace(POLICY, "if name not in allowed:", "if False:"),
    ),
    Probe(
        "skip-volume-reference-checks",
        "stop inspecting volume sources for privileged references",
        replace(POLICY, "errors.extend(self._check_volume_reference(",
                        "errors.extend([] or self._skip_volume_reference("),
    ),
    Probe(
        "skip-env-reference-checks",
        "stop inspecting env / envFrom for secret references",
        replace(POLICY, "errors.extend(self._check_env_references(",
                        "errors.extend([] or self._skip_env_references("),
    ),
    Probe(
        "permit-service-account-token-projection",
        "allow a projected API token regardless of configuration",
        replace(POLICY, 'elif key == "serviceAccountToken":\n'
                        "                        if not self.allow_service_account_tokens:",
                        'elif key == "serviceAccountToken":\n'
                        "                        if False:"),
    ),
    # -----------------------------------------------------------------
    # Workstream D: deployment identity vs workload identity.
    # -----------------------------------------------------------------
    Probe(
        "workload-may-be-the-deployer",
        "let a workload run as the ARES deployment identity",
        replace(POLICY, "if declared_sa == self.deployment_service_account:", "if False:"),
    ),
    Probe(
        "automount-may-be-implicit",
        "allow a workload to inherit the namespace default token silently",
        replace(POLICY, 'automount = pod_spec.get("automountServiceAccountToken")',
                        'automount = pod_spec.get("automountServiceAccountToken", False)'),
    ),

]


def _copy_platform(destination: Path) -> Path:
    root = destination / "platform"
    shutil.copytree(
        PLATFORM_ROOT,
        root,
        ignore=shutil.ignore_patterns(
            "__pycache__", "*.pyc", ".pytest_cache", "node_modules", ".git"
        ),
    )
    return root


def run_probe(probe: Probe, verbose: bool) -> tuple[bool, str]:
    with tempfile.TemporaryDirectory(prefix="k8s-mutation-") as tmp:
        root = _copy_platform(Path(tmp))
        try:
            probe.mutate(root)
        except MutationNotApplied as exc:
            return False, f"PROBE STALE: {exc}"
        completed = subprocess.run(
            [sys.executable, "-m", "pytest", *probe.tests, "-q",
             "--no-header", "-p", "no:cacheprovider"],
            cwd=root,
            env={"PYTHONPATH": str(root), "PATH": os.environ["PATH"], "HOME": tmp},
            capture_output=True,
            text=True,
        )
        tail = (completed.stdout or completed.stderr).strip().splitlines()
        summary = tail[-1] if tail else "(no output)"
        if verbose:
            print("\n".join(tail[-12:]))
        return completed.returncode != 0, summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true")
    parser.add_argument("-k", dest="filter", default="")
    parser.add_argument("-v", dest="verbose", action="store_true")
    args = parser.parse_args()

    selected = [p for p in PROBES if args.filter in p.name]
    if args.list:
        for probe in selected:
            print(f"{probe.name:34s} {probe.description}")
        return 0
    if not selected:
        print(f"no probes match {args.filter!r}")
        return 1

    print(f"Running {len(selected)} Kubernetes bypass probes "
          f"against an isolated copy.\n")
    escaped, redundant = [], []
    for probe in selected:
        caught, summary = run_probe(probe, args.verbose)
        if caught:
            label = "CAUGHT"
        elif probe.redundant_layer:
            label = "LAYERED"
            redundant.append(probe)
        else:
            label = "ESCAPED"
            escaped.append(probe)
        print(f"  [{label:7s}] {probe.name:34s} {summary}")

    print()
    if redundant:
        print(f"{len(redundant)} probe(s) absorbed by a sibling defence "
              f"(expected; combined probes prove the stack as a whole).")
    if escaped:
        print(f"{len(escaped)} MUTATION(S) ESCAPED -- the suite does not "
              f"detect these weakenings:")
        for probe in escaped:
            print(f"  - {probe.name}: {probe.description}")
        return 1
    print(f"All {len(selected)} mutations were caught "
          f"({len(selected) - len(redundant)} directly).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
