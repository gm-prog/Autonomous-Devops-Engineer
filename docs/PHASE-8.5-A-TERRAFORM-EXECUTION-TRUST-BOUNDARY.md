# Phase 8.5-A — Terraform Execution Trust Boundary v1

**Status:** see the single authoritative status section (§7). No other
section in this document states a status.

## 1. The problem this closes

Before this phase the deployment service executed Terraform directly on
the host with `subprocess.run(["terraform", …])`. Static checks in
`IaCValidator` rejected `local-exec`, `remote-exec` and `external` data
sources, and those checks remain — but they were never an execution
boundary.

Terraform is plugin-based. Providers and provisioners are executable
programs that Terraform discovers and runs during `init` and `plan`, so
"the Terraform text looks safe" and "this Terraform is safe to execute on
the host" are different statements. Making them different is the entire
point of this phase:

```
UNTRUSTED TERRAFORM
      -> STATIC VALIDATION      (early rejection)
      -> HOST-OWNED POLICY      (terraform_sandbox.py)
      -> ISOLATED SANDBOX       (container_terraform_sandbox.py)
      -> BOUNDED RUNTIME        (limits, timeout, bounded output)
      -> IMMUTABLE EVIDENCE     (policy identity in the plan hash)
```

## 2. Architecture

```
DeploymentEngine
   -> TerraformRunnerService          orchestration only, executes nothing
      -> TerraformSandboxPort         the single execution seam
         -> ContainerTerraformSandbox trusted host-side docker adapter
            -> isolated container     terraform runs here, and only here
```

| File | Role |
| --- | --- |
| `deployment_service/application/services/terraform_sandbox.py` | Pure, host-owned policy: operations, argv templates, limits, env allowlist, image/user/network/workspace validation, policy identity. Executes nothing. |
| `deployment_service/infrastructure/sandbox/container_terraform_sandbox.py` | Trusted adapter that drives the docker CLI on the host, classifies failures, cleans up unconditionally. |
| `deployment_service/application/services/terraform_runner.py` | Orchestrates fmt/init/validate/plan/apply through the port. Contains no `subprocess` import and no host fallback. |

The incident-service remediation sandbox was the security reference. It is
**not imported**: bounded contexts stay decoupled, and that sandbox was
not weakened to enable reuse.

## 3. Security model

### Execution

Terraform never runs as a host process of the deployment service. Both
paths are sandboxed — dry-run as well as approved execution — because
provider plugins can be invoked during `init` and `plan`. All four
Terraform entry points (`create_dry_run`, `execute`'s plan, `execute`'s
apply, and **rollback**) go through the same runner and therefore the same
boundary.

There is no generic "run this command" API. A closed `TerraformOperation`
enum (`FORMAT`, `INIT`, `VALIDATE`, `PLAN`, `APPLY`) maps to fixed argv
templates assembled by trusted code, and `build_run_plan` re-derives the
template and rejects argv that does not match it exactly, so extra flags
cannot be smuggled through. `argv[0]` is always the policy-owned
`terraform` binary; there is no shell, and no caller-defined executable.

### Isolation baseline

`--rm`, `--pull never`, digest-pinned image, non-root `--user`,
`--network none`, `--read-only` rootfs, tmpfs `/tmp` (`nosuid,nodev`),
`--cap-drop ALL`, `--security-opt no-new-privileges:true`,
`--pids-limit`, `--memory`, `--cpus`, a wall-clock timeout per operation,
and bounded stdout/stderr with explicit truncation.

Never present: `--privileged`, the Docker socket, host root/home/SSH/
credential mounts, `--pid=host`, `--network=host`, `--ipc=host`, arbitrary
devices. The docker CLI is invoked by the **trusted host-side orchestration
component**; the untrusted workload has no path to the daemon.

### Filesystem

Exactly one bind mount: the ephemeral per-run workspace at `/workspace`.
It is read-write — unlike the remediation sandbox — because `init` writes
`.terraform/` and `plan -out` writes the saved plan. It is an ephemeral
host-created directory holding content the caller already supplied, so
write access grants the workload nothing it did not bring.

The workspace must be absolute, must exist, must contain no `..`, and
must resolve beneath `DEPLOYMENT_WORKSPACE_ROOT` when that is configured
(symlinks are resolved first, so a symlink inside the root cannot escape
it). Saved plan paths must be a direct child of the workspace: a plan path
outside it is refused rather than rewritten.

### Network

`network = none` is the v1 default **and the only permitted value**. There
is deliberately no request-level, repository-level or environment-level
switch — neither an API caller nor AI-generated Terraform can turn
networking on. Enabling it requires editing
`SANDBOX_ALLOWED_NETWORK_MODES` in the policy module, which changes the
policy identity (§5).

### Environment and credentials

The sandbox environment is an explicit allowlist of **constant** values.
The host environment is never copied, so `JWT_SECRET`, `DATABASE_URL`,
`REDIS_URL`, GitHub tokens and Docker configuration cannot leak in.

Credentials are opt-in by **name** through `DEPLOYMENT_CREDENTIAL_ENV_KEYS`
and are forwarded only on the execution path — dry-run gets none.
Credential **values never enter argv**: the plan passes `-e NAME` and the
adapter supplies the value through the docker CLI's own process
environment. Names on the forbidden list (secrets, `PATH`, `DOCKER_*`) can
never be forwarded even if configured, and a configured credential that is
absent on the host fails closed rather than running without it.

## 4. Fail-closed semantics

Every one of these means **Terraform did not execute**, and none of them
can produce `PASS`:

| Condition | Result |
| --- | --- |
| image unconfigured / floating tag / malformed digest | `BLOCKED` `SANDBOX_CONFIGURATION_ERROR` |
| image absent locally (`--pull never`) | `BLOCKED` `SANDBOX_CONFIGURATION_ERROR` |
| docker CLI missing, daemon unreachable | `BLOCKED` `SANDBOX_UNAVAILABLE` |
| root user, non-`none` network, bad workspace, bad argv | `BLOCKED` `SANDBOX_POLICY_VIOLATION` |
| malformed sandbox result | `BLOCKED` `SANDBOX_RESULT_INVALID` |
| wall-clock timeout | `TIMEOUT` (process group killed, container removed) |
| plan succeeded but produced no saved plan | `BLOCKED` |
| saved plan missing or modified before apply | `BLOCKED` `PLAN_ARTIFACT_MISSING` / `PLAN_ARTIFACT_MISMATCH` |

"Sandbox unavailable" never means "run Terraform on the host".

## 5. Policy identity and plan binding

`sandbox_policy_identity()` is a deterministic fingerprint —
`terraform-sandbox-v1:<sha256[:32]>` — over the image digest, user,
network mode, Terraform version, capability/rootfs policy, resource
limits, output bound, workspace mount and the allowed operation set. It
contains no timestamps and no random values, so it is stable for a posture
and changes the moment the posture does.

That identity participates in `DeploymentEngine._plan_hash`, so the same
artifact planned under a materially different trust boundary does **not**
silently reuse an earlier approval identity.

Saved plans are treated as sensitive ephemeral artifacts: never logged,
never printed, never committed. The runner records only their SHA-256, and
`apply` re-verifies the bytes against the hash recorded at plan time
before applying **exactly** that plan — never a regenerated one.

## 6. Provider and module limitation (read this before enabling clouds)

With `network = none`, Terraform cannot download providers or remote
modules. Configurations needing an external provider **fail closed**; the
boundary is never relaxed to make them work.

The committed zero-cloud E2E fixture (`e2e/terraform/main.tf`) uses only
built-in `terraform_data`, so it needs no registry access and stays
executable under this profile.

Enabling external providers is a **separate, reviewed phase**: it needs a
pre-provisioned provider distribution (filesystem mirror or vendored
plugin directory) plus a lock-file policy. `.terraform.lock.hcl` is
deliberately **not** introduced here: repository inspection showed it is
not required for the zero-provider profile, and adding an artifact to
request validation, hashing, approval binding and replay merely because it
sounds secure would have been unjustified scope.

## 6a. Corrective (Phase 8.5-A-C): runtime wiring and approval integrity

The first 8.5-A implementation built a correct sandbox *abstraction* but
left four acceptance-blocking gaps. They are closed as follows.

### Runtime topology — the sandbox can now actually run

The deployment-service image had no Docker CLI, and nothing mounted a
container runtime socket, so the adapter had nothing to talk to. The
corrective adopts the **acceptable v1 fallback**: the deployment service
is treated as trusted infrastructure control-plane code and is given the
minimum runtime access needed to launch the sandbox.

```
deployment-service container          <- TRUSTED control plane
  |  docker CLI (docker-ce-cli only, no daemon)
  |  /var/run/docker.sock             <- control-plane authority
  v
Docker daemon (host)
  |
  v
terraform sandbox container           <- UNTRUSTED workload
     --network none --read-only --cap-drop ALL
     --security-opt no-new-privileges --user 65532:65532
     --pids-limit --memory --cpus --rm --pull never
     NO docker socket, NO host mounts, ONE workspace bind
```

Why this is acceptable for v1, and what it costs: the socket grants the
deployment service effective root on the host daemon. That authority is
confined to one service whose Docker invocation is fixed and
policy-built — there is no generic "run a container" API — and it is
never propagated into the workload. A dedicated sandbox-runtime service
remains the preferred end state; this is a deliberate, documented
residual risk, not an oversight.

**Terraform was removed from the control-plane image.** The control plane
launches containers; it does not run Terraform. The image build now fails
if a `terraform` binary is present, so "never exec host terraform" is a
physical property, not a coding rule.

### Workspace contract

| Property | Value |
| --- | --- |
| root | `DEPLOYMENT_WORKSPACE_ROOT` (E2E: `/tmp/ares-e2e-tf-workspaces`) |
| host visibility | bind-mounted at the **same absolute path** on host and control plane |
| per-run path | `<root>/approved-<run_id>` |
| ownership | `DEPLOYMENT_TERRAFORM_SANDBOX_UID:GID` (default 65532, never 0) |
| permissions | `0o2770` — owner+group only, setgid; never `0o777` |
| sandbox mount | exactly one `-v <workspace>:/workspace:rw` |
| cleanup | on non-approval dry-run failure, and on every terminal state |

The daemon resolves bind sources on the **host**, so a path that exists
only inside the control-plane container would silently mount the wrong
thing. Identical absolute paths on both sides is a correctness
requirement, not a convenience.

### Non-root permission contract

The sandbox UID/GID and the workspace owner are resolved by one helper,
so they cannot drift. If the control plane is unprivileged the sandbox
reuses its identity (no `chown` needed); if it is root it hands ownership
to an unprivileged identity explicitly. A configured UID of 0 is refused.
No `chmod 777`, and no "fix" that runs Terraform as root.

### Exact-plan approval (the most important change)

Before, approval was meaningless in a way the tests did not reveal:

```
dry run : plan A -> hash(A) -> workspace DELETED
approve : hash(A)
execute : plan B -> hash(B) -> apply B      <- A was never applied
```

Hashing B against itself always succeeds. The corrected contract:

```
dry run : plan A -> saved to a persistent, owned workspace
approve : binds A's exact BYTES (plan_file_hash is in the plan identity)
execute : recover A -> re-verify A -> terraform init -> apply A
```

`execute()` performs **no plan operation**. `init` is permitted and
counted separately because it cannot create or alter a plan. A missing,
modified, replaced or symlinked plan, a deleted workspace, or a changed
credential profile all fail closed before anything is applied, and a
terminal run destroys its saved plan so it can never be replayed.

### Plan-artifact safety

The saved plan is written by untrusted Terraform into a directory it
controls, so every host-side touch goes through one guard
(`plan_artifact.py`) that proves: direct child of the resolved
workspace, exact expected filename, no symlink in any path component,
regular file, size-bounded, still confined after resolution, and opened
with `O_NOFOLLOW` so a check/read race also fails closed. Four
independent layers; the mutation harness proves the stack as a whole.

### Credential context

v1 forwards **no credentials** (`DEPLOYMENT_CREDENTIAL_ENV_KEYS=`), so the
profile identity is `credentials-disabled`. The profile is derived from
credential **names only** — never values, and never a hash of a value —
and is bound into plan identity, so switching credentials on after
approval is rejected.

### What the policy identity does and does not prove

`sandbox_policy_identity` fingerprints the requested policy: image
reference, user, network, limits, capability/rootfs posture, workspace
mount and allowed operations. It proves what the control plane
**asked for**. It does not, by itself, prove what the kernel delivered,
and the declared `DEPLOYMENT_TERRAFORM_SANDBOX_VERSION` is a label, not a
measurement of the binary. The **image digest** is the runtime trust
anchor; the live E2E is what confirms the delivered runtime. The default
Docker seccomp profile is relied upon as-is — no custom seccomp profile
exists and none is claimed.

## 7. Operational status — the one authoritative status section

**LIVE E2E: PASS**

This is the only status statement in this document. Any status wording
elsewhere is historical narrative and is not authoritative.

The proof is the CI job **"Phase 8.5-A containerized deployment-service
E2E"** (`e2e/terraform_sandbox_container_e2e.py`). It never imports the
application. It builds the control-plane and sandbox images, pushes the
sandbox to a registry to obtain a real digest, pulls it back by digest,
starts the **real deployment-service container** together with the Redis
it depends on, and drives the whole deployment through HTTP only:
`POST /api/internal/deployments/dry-run`, `/{run_id}/approve`,
`/{run_id}/execute`, `GET /{run_id}`. The machine-readable result for the
commit under review is `docs/phase-8.5-a-closeout-evidence.json`; a green
job on an earlier commit is not evidence for a later one.

### REQUESTED versus OBSERVED

"Requested" is what the policy asks the daemon for. "Observed" is what
the harness measured from inside the running container or from the host.
Only the observed column is evidence.

| Property | Requested | Observed |
| --- | --- | --- |
| Terraform runs non-root | `--user 65532:65532` | `uid=65532 gid=65532` read from the running container |
| Capabilities dropped | `--cap-drop ALL` | `CapEff=0000000000000000` from `/proc/self/status` |
| No new privileges | `--security-opt no-new-privileges:true` | `NoNewPrivs: 1` from `/proc/self/status` |
| Network disabled | `--network none` | `/proc/net/dev` shows loopback only; unreadable ⇒ FAIL, never PASS |
| Read-only root filesystem | `--read-only` | `ro` flag on the `/` mount in `/proc/self/mountinfo` — a read-only **mount**, not a permission denial |
| Mounts | workspace only | mountinfo enumerated against a permitted set; unexpected host mounts absent |
| Docker socket withheld | not passed to the sandbox | absent in the sandbox, present in the control plane |
| Image identity | digest-pinned, `--pull never` | digest resolved from the registry during the run, never hand-written |
| Terraform version | label `1.9.8` | `terraform version` output from the running image |
| Workspace ownership | sandbox identity, `2770` | `65532:65532 2770` observed on the host; the saved plan is `65532:65532 644` |
| Credentials | none configured | `credentials-disabled`; names only, never values |

### Scope limits that remain true

* The sandbox image is **host-configured** via
  `DEPLOYMENT_TERRAFORM_SANDBOX_IMAGE` and **must** be digest-pinned;
  anything else is refused. `DEPLOYMENT_TERRAFORM_SANDBOX_VERSION` is a
  label recorded in evidence, not a measurement of the binary; the
  observed version comes from the running image.
* `.terraform/` is **legitimately absent** from the approval workspace.
  The zero-cloud fixture declares no providers and the sandbox runs with
  `--network none`, so provider installation cannot occur. The harness
  records this as an observation and instead asserts that the non-root
  sandbox wrote the plan artifact into the shared workspace.
* Kubernetes is **stubbed** at the test topology and is **not** validated
  by this result. Its hardening is a separate phase.
* The control plane holds the Docker socket. That is the documented v1
  residual risk (§6): the deployment-service container is **not**
  host-isolated, and this phase does not claim it is.
* This agent's own sandbox has **no Docker CLI and no daemon**, so the
  driver reports BLOCKED when run here. All container evidence comes from
  CI.
* Docker runtime availability remains a trusted-infrastructure dependency
  of the host orchestration side.
* This phase does **not** make the platform "production-ready autonomous
  cloud Terraform". It makes untrusted Terraform non-executable on the
  host.

## 8. Explicitly out of scope

Kubernetes execution hardening is a **separate** follow-up phase.
`kubectl_runner.py` is untouched: its namespace allowlist, credentials,
rollout semantics and verb set are unchanged and were not weakened. The
Kubernetes validator still covers only a subset of the Restricted Pod
Security controls (`allowPrivilegeEscalation`, `runAsNonRoot`, seccomp,
capabilities, host namespaces, hostPath, restricted volume types) — that
remediation belongs to that phase, not this one.
