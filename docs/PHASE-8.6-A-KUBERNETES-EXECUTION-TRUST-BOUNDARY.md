# Phase 8.6-A — Kubernetes Execution Trust Boundary v1

**Status:** implemented; live-cluster proof runs in CI (`kubernetes-kind-e2e`).
**Scope:** Kubernetes only. Phase 8.5-A Terraform semantics are frozen and unchanged.

This document describes what the boundary is, what it refuses, and —
explicitly — what it does *not* prove.

---

## 1. Why this phase exists

Before 8.6-A, Kubernetes was the weakest execution path in the platform,
and materially weaker than Terraform.

`IaCValidator._kubernetes()` parsed the manifest but inspected only four
fields (`hostNetwork`, `hostPID`, `hostPath`, `privileged`) and only
under `spec.template.spec`. `KubectlRunnerService` then executed
`kubectl` as an ordinary host process, with `os.environ.copy()` on the
dry-run path.

Eight attacks were run against the pre-8.6-A validator as a
reproduction step. **All eight were ACCEPTED:**

| Attack | Pre-8.6-A result |
| --- | --- |
| `ClusterRole` with `apiGroups/resources/verbs: ["*"]` | PASS |
| `ClusterRoleBinding` → `cluster-admin` | PASS |
| `Deployment` into `kube-system` | PASS |
| Bare Pod with `hostNetwork` + `privileged` | PASS (only `spec.template.spec` was read) |
| `hostIPC` + `hostPort` + `SYS_ADMIN` + `allowPrivilegeEscalation` | PASS |
| Privileged **initContainer** | PASS |
| Arbitrary `serviceAccountName` | PASS |
| `Service` `type: NodePort` + `externalIPs` | PASS |

These eight cases, plus 30 more, are now committed negative tests.

---

## 2. Threat model

**Untrusted:** the generated Kubernetes manifest, everything derived from
an LLM, and every field of the inbound HTTP request.

**Trusted:** the deployment service process, the host-owned policy
configuration, the sanitizer, the command policy, and the container
adapter.

**Adversary goal:** make the trusted system execute a Kubernetes
operation outside the namespace/resource/verb policy — by widening the
manifest, by switching the namespace or cluster, by weaponising the
kubeconfig, or by escaping the sandbox.

**Assumed capability:** the adversary fully controls manifest bytes and
request fields. It does not control the host filesystem, the policy
source, or the committed pins.

---

## 3. Trust boundaries

```
 untrusted manifest
        │
        ▼
 ┌─────────────────────────────┐
 │ KubernetesManifestPolicy    │  parsed YAML; DENY by default
 │  (host-owned)               │  rejects — never rewrites
 └─────────────────────────────┘
        │ canonical manifest + sha256
        ▼
 ┌─────────────────────────────┐
 │ KubectlRunnerService        │  closed operation enum
 │  (no subprocess import)     │  host-owned namespace only
 └─────────────────────────────┘
        │ KubectlSandboxStep (fixed argv)
        ▼
 ┌─────────────────────────────┐
 │ ContainerKubectlSandbox     │  the ONLY process spawner
 │  (trusted adapter)          │  spawns docker, never kubectl
 └─────────────────────────────┘
        │ docker run (locked down)
        ▼
 ┌─────────────────────────────┐
 │ kubectl sandbox container   │  non-root, ro rootfs, cap-drop ALL
 └─────────────────────────────┘
        │ https, CA-pinned, token
        ▼
   API server ── RBAC ── PSA(restricted) ── namespaced resources
```

---

## 4. Manifest model

Implemented in `deployment_service/application/services/kubernetes_manifest_policy.py`.

* **Parsed YAML**, multi-document aware. Not a regex scanner — the
  previous phase's explicit instruction was not to grow the IaC
  validator into a fragile regex security parser.
* **Versioned allowlist**, derived from what the repository actually
  deploys. An audit of every `kind:` in the repo found exactly one
  deployable resource (`apps/v1 Deployment`, `e2e/fixtures/k8s-deployment.yaml`).
  The allowlist is `apps/v1 Deployment`, `v1 Service`, `v1 ConfigMap` —
  the Deployment plus the two namespaced companions it may legitimately
  need. A strict allowlist therefore breaks nothing that exists today.
* **Hard-denied kinds** override any configured widening: all RBAC kinds,
  `ServiceAccount`, `Namespace`, CRDs, webhook configurations, `Node`,
  `PersistentVolume` and the rest of the cluster-scoped surface. A
  generated manifest can never define its own authorization.
* **One namespace.** `DEPLOYMENT_KUBERNETES_NAMESPACE` is host-owned. A
  manifest that declares a different namespace is rejected, not
  corrected. The canonical form injects the host-owned namespace.
* **Restricted pod security**: `runAsNonRoot`, `seccompProfile` in
  `{RuntimeDefault, Localhost}`, `allowPrivilegeEscalation: false`,
  `drop: [ALL]`, no `capabilities.add`, no `runAsUser: 0`.
* **Rejects** `hostNetwork`, `hostPID`, `hostIPC`, `hostPath`,
  `hostPort`, `privileged`, `ephemeralContainers`.
* **All containers** are checked: `containers`, `initContainers` and
  `ephemeralContainers` — the pre-8.6-A gap.
* **Volumes** are classified: an unknown volume source is denied, not
  ignored.
* **Services** are ClusterIP-only; `externalIPs` and `nodePort` are
  refused.
* **Resources** must declare bounded cpu/memory requests *and* limits.
* **Rollout target names** come from the validated manifest. The HTTP
  request cannot supply one.

Canonical form is `yaml.safe_dump_all(sort_keys=True, explicit_start=True)`
with the namespace injected; the approval hash is SHA-256 of those bytes.

---

## 5. Namespace model

One namespace, host-owned, in three independent places:

1. the manifest policy rejects a declared mismatch;
2. the runner rejects a caller-supplied mismatch;
3. the command policy rejects reserved system namespaces
   (`kube-system`, `kube-public`, `kube-node-lease`, `default`,
   `local-path-storage`) and any name over 63 characters.

Layer 3 is defence in depth below layers 1 and 2.

---

## 6. RBAC model

`deployment_service/infrastructure/kubernetes/rbac_profile.py` is the
single source of the profile, used both to generate the applied YAML and
to drive the assertions, so manifest and test cannot drift.

* Namespaced `Role` + `RoleBinding`. **No `ClusterRole`, no
  `ClusterRoleBinding`** — a cluster-scoped grant would make the
  namespace boundary cosmetic.
* Built from DENY by listing what the four operations call, not by
  trimming an admin role.
* No wildcards. No `escalate`, `bind`, `impersonate`, `proxy`, `delete`,
  `deletecollection`.
* **No secret reads.** No permitted operation needs one.
* `pods` and `replicasets` are read-only.

Denials are proven with real `kubectl auth can-i` SubjectAccessReviews
against the live API server as
`system:serviceaccount:<ns>:ares-deployer` — 12 namespaced expectations
and 7 cluster-scoped denials. **Inspecting the YAML is not the proof**: a
correct-looking Role can still be bound incorrectly.

---

## 7. Kubeconfig and credential-plugin model

A kubeconfig is **not inert data** — `exec` credential plugins run an
external binary chosen by the file. The sanitizer therefore never
forwards the operator's file; it **rebuilds** a minimal one.

Refused: `exec`, `auth-provider`, basic auth, impersonation keys
(`act-as*`, `as*`), `client-certificate` / `client-key` / `tokenFile`
*paths*, any unknown user key, `proxy-url`, `insecure-skip-tls-verify`,
`tls-server-name`, non-`https` endpoints, endpoints with a path or
embedded credentials, missing or non-PEM CA data, and a context
namespace that disagrees with the host-owned one.

Accepted: exactly one cluster, one user, one context, one namespace,
with inline credentials — either a token or a client cert/key pair,
never both.

A `kuberc` with `credentialPlugins.policy: DenyAll` is mounted
read-only. Because older kubectl versions ignore that file, the
sanitizer's `exec` rejection is the load-bearing control and the kuberc
is the second layer.

**Cluster identity** = normalised endpoint + SHA-256 of the CA bundle.
It is non-secret and bound into the approval. No credential value is
ever logged, returned, or hashed into an identity.

---

## 8. Network model

kubectl **must** reach the API server, so `--network none` is impossible
here. This is the one structural difference from the Terraform sandbox.

* Egress is **destination-controlled**: a dedicated host-owned Docker
  network joined to the cluster network.
* `host`, `none`, `bridge` and `container` modes are all refused by
  `KubectlSandboxSpec`. A request can never select the network.
* Proxy environment variables are **never** inherited — a hostile host
  environment must not be able to redirect API traffic.
* The live E2E asserts both directions: the API server **is** reachable,
  and an unrelated destination **is not**.
* No step depends on Internet access. The workload image is loaded
  directly into the cluster's image store.

---

## 9. Sandbox runtime

`--rm`, digest-pinned image, `--pull never`, non-root `65532:65532`,
`--read-only` rootfs, `tmpfs /tmp` (`nosuid,nodev,size=32m`),
`--cap-drop ALL`, `--security-opt no-new-privileges:true`,
`--pids-limit 128`, memory and CPU limits, wall-clock timeout per
operation, output bounded to 128 KiB and credential-redacted.

**No Docker socket.** No host PID, IPC or network namespace. Exactly
three read-only mounts: the approved manifest at
`/workspace/deployment.yaml`, the sanitized kubeconfig at
`/run/secrets/ares/kubeconfig`, and the kuberc.

The environment handed to kubectl is constructed from nothing —
`os.environ.copy()` appears nowhere on this boundary, and an AST-based
test enforces that (a grep would false-positive on this very document).

---

## 10. Command allowlist

Four operations, no more:

| Operation | argv |
| --- | --- |
| `SERVER_SIDE_DRY_RUN` | `kubectl apply --server-side --dry-run=server --validate=strict --field-manager=ares -f /workspace/deployment.yaml -n <ns>` |
| `APPLY` | `kubectl apply --server-side --validate=strict --field-manager=ares -f /workspace/deployment.yaml -n <ns>` |
| `ROLLOUT_STATUS` | `kubectl rollout status deployment/<name> -n <ns> --timeout=<n>s` |
| `ROLLOUT_UNDO` | `kubectl rollout undo deployment/<name> -n <ns>` |

There is **no** `sandbox.run(cmd)`. A test asserts that no generic
command entry point exists.

No request field can reach the executable, kubeconfig path, namespace,
field manager, flags, proxy, server, TLS settings, filename or
subcommand. `exec`, `cp`, `attach`, `port-forward`, `proxy`, `plugin`,
`delete`, `patch`, `scale`, `run`, `edit`, `config`, `auth`, `debug` and
others are rejected by the step validator. `-f` must equal exactly
`/workspace/deployment.yaml`; URLs, directories, `-k` and stdin are
refused.

`--dry-run=client --validate=false` is gone. Validation is server-side
and strict, against the real cluster, and **fails closed** — there is no
client-side fallback, because a client dry run proves nothing about
admission, RBAC or schema and reporting it as a pass would be a false
result.

---

## 11. Approval integrity

The exact approved manifest is canonicalised and hashed; the canonical
bytes — never the raw input — are what execute. The applied hash is
compared with the approved hash in the live E2E.

Approval identity binds: manifest hash, sandbox policy identity,
manifest policy identity, credential profile, namespace, and cluster
identity (endpoint + CA fingerprint). It contains no raw credentials and
no timestamps, so it is reproducible.

`sandbox_policy_identity()` covers the image digest, kubectl version,
user, network, limits, operation set, mount paths, field manager and
environment key set. **If the posture weakens, the identity changes**, so
an approval granted under a stronger posture cannot execute under a
weaker one.

---

## 12. Rollback

Rollback runs through the same sandbox, the same namespace, the same
credential profile and the same cluster path as deployment — it is not a
privileged side door. It is tested separately in the live E2E, after a
second revision is created. The existing deployment state machine
(`AWAITING_APPROVAL` … `ROLLBACK_FAILED`) is unchanged; no second state
machine was introduced.

---

## 13. E2E topology

`e2e/kubernetes_sandbox_kind_e2e.py`, CI job `kubernetes-kind-e2e`.

Real kind cluster `ares-e2e` (control-plane + worker, node image from
the committed pin) · real Pod Security Admission with
`enforce/audit/warn = restricted` on the deployment namespace · real
ServiceAccount, Role and RoleBinding · a real short-lived ServiceAccount
token · the real sandbox container · real kubectl from a committed,
checksum-verified pin (`v1.31.4`) · the real API server.

**There is no stub kubectl in this driver.** `write_kubectl_stub()`
exists elsewhere for unit tests and is never the authoritative proof.

The driver exits `0` only if every check passed, `1` on any failure, and
`2` = BLOCKED when the environment cannot host the proof. A BLOCKED run
is never reported as a pass.

---

## 14. Mutation probes

`scripts/mutation_probe_kubernetes_boundary.py` — 38 committed probes.
Each weakens one control on a throwaway copy and the suite must notice.

Three probes are marked `redundant_layer`: emptying the hard-deny kind
list, removing the volume allow-list check, and removing `exec` from the
kubeconfig deny list. Each is absorbed by a sibling layer, and each has
a paired **combined** probe that strips every layer at once — so
"defence in depth" is demonstrated rather than asserted.

Two probes exposed tests that were passing **for the wrong reason**
(the privileged check and the service-type check were masked by other
violations in the same fixture). Both were fixed with isolating tests
that violate exactly one rule.

---

## 15. Residual risks

1. **The sandbox base image is the committed `python:3.11-slim` pin, not
   a distroless/scratch image.** It therefore carries a shell and a
   Python runtime that kubectl does not need. This was chosen for build
   reliability, since no container runtime exists in the authoring
   workspace to validate a scratch-based image. Reducing the base is the
   single highest-value follow-up.
2. **Egress is destination-controlled at the Docker-network level, not
   by a Kubernetes NetworkPolicy or an egress proxy.** Any other
   container attached to the same network would be reachable. A
   dedicated network per run, or an explicit egress allowlist, would be
   stronger.
3. **kuberc `DenyAll` is not load-bearing on older kubectl versions.**
   The sanitizer's `exec` rejection carries the control.
4. **Approval binding is enforced in-process.** The approved manifest is
   re-derived and re-hashed at execution time, but there is no
   independent signer; a compromised deployment-service process could
   approve its own manifest.
5. **Service and ConfigMap are allow-listed but unexercised** — the
   repository deploys neither today, so their policy paths are proven by
   unit tests only, not by the live cluster.
6. **The ServiceAccount token is short-lived but not rotated
   mid-run**, and has no audience restriction.
7. **Pod Security Admission is enforced on the deployment namespace
   only.** Cluster-wide PSA defaults are not configured here.
8. The platform is **not** "production-ready autonomous Kubernetes."
   "Validated" means the manifest satisfies the policy; it does not mean
   the workload is safe to run.

---

## 16. What this phase does *not* claim

* It does not claim Terraform semantics changed. They are frozen.
* It does not claim any proof that CI did not actually execute.
* A green unit suite is **not** the containerized runtime proof; the two
  are reported separately and are separate CI jobs by design.
