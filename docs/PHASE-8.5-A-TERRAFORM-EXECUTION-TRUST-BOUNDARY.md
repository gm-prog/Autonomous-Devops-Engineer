# Phase 8.5-A — Terraform Execution Trust Boundary v1

**Status:** implemented and unit-verified. Live E2E execution of the
sandbox is **NOT VERIFIED** (see §7).

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

## 7. Operational status — honest scope

* The sandbox image is **host-configured** via
  `DEPLOYMENT_TERRAFORM_SANDBOX_IMAGE` and **must** be digest-pinned;
  anything else is refused. `DEPLOYMENT_TERRAFORM_SANDBOX_VERSION` records
  the Terraform version in evidence. The repository's established
  Terraform version is **1.9.8** (`deployment_service/Dockerfile.e2e`) and
  was not changed.
* **Live E2E execution of the sandbox is NOT VERIFIED.** No sandbox image
  has been built, pulled or executed, and no Terraform has run inside a
  container as part of this phase. Unit tests prove policy and
  orchestration; they are not a live run.
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
