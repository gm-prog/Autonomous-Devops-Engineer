# Phase 8.8A — Kubernetes Rollback Safety and Operation Provenance: Research, Architecture Decision and Failure-Mode Audit

Research-only artifact. Written 2026-11-14 against `fix/p2-recovery-cleanup` at
`72189146ceb3206a9ecd7a8734d26cac7ab16275` with the uncommitted P2-A/P2-B candidate present in the
working tree. **No application code, tests, CI, migrations or infrastructure were modified by this
research.** Every claim is labeled:

- **[Verified in local source]** — read directly from this working tree.
- **[Verified by test evidence]** — executed in this checkout and recorded in the work log.
- **[Official external documentation]** — kubernetes.io pages cited in §15.
- **[Engineering recommendation]** — a design decision proposed by this document.
- **[Unverified hypothesis]** — plausible but not proven here; must be validated by the
  implementation session or on a real cluster.

---

## 1. Executive findings

1. **Root cause (confirmed).** `_rollback()` iterates every Deployment name parsed from the
   submitted manifest and calls `kubectl.rollout_undo` unconditionally, before any check of whether
   a Kubernetes apply was ever handed to the sandbox. It is reached after a Terraform apply failure,
   after a Kubernetes apply failure, and after a health-check failure. A Terraform failure that
   occurs *before* Kubernetes is reached therefore mutates an untouched workload. **[Verified in
   local source]** (`deployment_engine.py` lines 575–634, 1224–1228, 1246–1250, 1260–1264).
2. **No durable operation-provenance exists for Kubernetes attempts.** The only durable
   evidence in `run.execution` is `kubernetes_apply` (the runner's result payload), written in
   memory after `sandbox.execute()` returns and persisted only by the *next* fenced commit. There
   is no pre-handoff intent record and no per-attempt journal for Kubernetes, in contrast to the
   P1-2 dispatch journal for broker publishes. A worker killed between handoff and the next commit
   leaves a durable record that cannot distinguish "never attempted" from "attempted, result
   lost". **[Verified in local source]**
3. **`kubectl rollout undo` is unpinned.** `build_kubectl_argv()` emits
   `kubectl rollout undo deployment/<name> -n <ns>` with no `--to-revision`; officially,
   omitting the flag means `--to-revision=0`, i.e. "rollback to the last revision" — a target that
   is defined by the *cluster's own revision history*, not by this run. **[Verified in local
   source]** + **[Official external documentation]**
4. **Rollout undo cannot deliver manifest rollback.** Officially, a Deployment revision is created
   *only when `.spec.template` changes*, and a rollback restores *only the Pod-template part*.
   Service and ConfigMap mutations are never compensated, resources created by the apply are never
   removed (and `delete` is a forbidden subcommand in the sandbox policy), and `DEFAULT_ALLOWED_
   RESOURCES` admits Deployment + Service + ConfigMap while rollback compensates only Deployment
   pod templates. The current `ROLLED_BACK` status overstates what was done. **[Verified in local
   source]** + **[Official external documentation]**
5. **Truthfulness defect:** a rollback whose component list is empty is computed as `PASS` and the
   run is moved to `ROLLED_BACK`. A Terraform-declared run with no Deployment in the manifest whose
   Terraform apply fails reports `ROLLED_BACK` having executed zero rollback components.
   **[Verified in local source]**
6. **Stale-worker cleanup race (confirmed in the current candidate).** When worker A loses its
   lease, `_mark_lease_lost()` sets A's *local* state to `LEASE_LOST` regardless of whether the
   fenced commit was accepted (its return value is ignored). `execute()`'s `finally` then destroys
   the **shared per-run approval workspace** (`approved-{run_id}`) because `LEASE_LOST ∈
   _TERMINAL_STATES`. If worker B holds a newer fence and is resuming from the persisted document,
   B's `_verify_approved_plan_recoverable()` then fails ("workspace no longer exists") and B fails
   the run. The P2 candidate fixed the *setup* re-read path but not the *execution finally* path.
   **[Verified in local source]**
7. **Recommendation summary.** Record a versioned, bounded per-attempt evidence record inside
   `run.execution` (persisted by the same fenced commit that guards state), with a monotonic
   `may_have_mutated` fact; gate every `rollout_undo` on durable handoff evidence plus a
   conservative legacy rule; represent rollback completeness as truthful `run.rollback` metadata
   (no new state-machine transitions); fix the stale-worker workspace disposal to depend on
   fencing-confirmed terminality; and defer pinned-revision/pre-state-capture/conditional
   restoration to a separately scoped compensation subsystem. **[Engineering recommendation]**

## 2. Verified local source paths and symbols

All paths relative to `devops-ai-platform/`. Line numbers refer to the current working tree.

| File | Symbols verified |
|---|---|
| `deployment_service/application/services/deployment_engine.py` | `execute()` (1022), `_rollback()` (575), `_commit()` (638), `_require_lease()` (660), `_mark_lease_lost()` (703), `_handle_lease_loss()` (716), `_deployment_names()` (292), `_write_iac()` (306), `_new_workspace()` (321), `_approval_workspace()` (336), `_discard_approval_workspace()` (369), `_verify_approved_plan_recoverable()` (523), `_approved_kubernetes_identity()` (223), `_kubernetes_is_declared()` (200), `_kubernetes_not_applicable()` (275), `_TERMINAL_STATES` (70), `_COMMIT_RETRIES/_COMMIT_RETRY_DELAY` (88–89), ExitStack registration and `finally` (1077–1133, 1291–1297) |
| `deployment_service/application/services/kubectl_runner.py` | `KubectlRunnerService._execute()` (202), `apply()` (321), `rollout_status()` (344), `rollout_undo()` (362), `MUTATING_OPERATIONS` (200), `_approved_manifest()` (178), `_kubeconfig()` (110), `execution_identity()` (154), `_resolve_sandbox()` (138), result payload construction (269–292) |
| `deployment_service/application/services/kubectl_sandbox.py` | `KubectlOperation` (58), `OPERATION_TIMEOUTS` (68), `FORBIDDEN_SUBCOMMANDS` (76), `build_kubectl_argv()` (86) — `ROLLOUT_UNDO` branch (155–160), `KubectlSandboxStep.__post_init__` (173), `FIELD_MANAGER = "ares"` (37), `sandbox_policy_identity()` (348), `load_spec_from_environment()` (374) |
| `deployment_service/application/services/kubernetes_manifest_policy.py` | `DEFAULT_ALLOWED_RESOURCES` (51–55), `HARD_DENIED_KINDS` (60), operator widening `DEPLOYMENT_K8S_ALLOWED_RESOURCES` (233–235), per-document kind checks (318–376) |
| `deployment_service/application/services/kubernetes_execution_identity.py` | `KubernetesExecutionIdentity` (38), `digest()` (53), `verify_binding()` (199), `expected_api_server()` (183) |
| `deployment_service/application/services/health_check_service.py` | `check()` (41) — returns `FAIL` with "No deterministic health signal was configured." when the deployment-name list is empty |
| `deployment_service/infrastructure/persistence/execution_lease.py` | `ACQUIRE/RELEASE/RENEW/OWNERSHIP_ASSERTION/COMMIT` scripts, `ExecutionLeaseGuard.acquire/assert_owned/commit/release` (195/270/317/337), watchdog (239), `alive()` (265) |
| `deployment_service/infrastructure/persistence/redis_pipeline_store.py` | `SAVE_BUMP/SAVE_CAS/REVERT_DISPATCH_CAS` scripts, revision counter, `journal_dispatch_attempt()` (257), `read_dispatch_journal()` (283), `all_attempts_pre_send_failed()` (303), `has_unresolved_attempt()` (313) — the P1-2 **dispatch** journal |
| `deployment_service/domain/entities/deployment_run.py` | `DeploymentRun.to_dict()` (74), `from_dict()` (127), `execution` dict (44), `rollback` dict (46), derived provenance (105) |
| `deployment_service/domain/value_objects/deployment_state.py` | full `_ALLOWED` transition table (35–87), `LEASE_LOST` (28–32) |
| `deployment_service/infrastructure/sandbox/container_kubectl_sandbox.py` | `execute()` (312), `_run_container()` (359) — cancel/timeout kill semantics, `KubectlSandboxResult` (67) |
| `deployment_service/tests/test_deployment_engine.py` | `FakeKubectl` (291), P2-A/P2-B regression tests (561–946) |
| `deployment_service/tests/test_execution_lease.py` | live-Redis harness conventions (62–80) |
| `.github/workflows/ci.yml` | jobs `security-integrity`, `redis-integration`, `structural-guards`, `kubernetes-trust-boundary`, `kubernetes-kind-e2e`, `kubernetes-service-http-e2e`; pinned `redis:7.2-alpine@sha256:29e8589c…` (lines 68, 288); `REDIS_INTEGRATION_REQUIRED=true` steps |
| `e2e/pinned-kubectl.txt` | kubectl `v1.31.4`, sha256 `298e19e9…5620f` |
| `security_guards/runtime_guard.py` | `_check_redis_integration_contract()` (49) — which live-Redis steps the structural guard recognizes |

**[Verified in local source]** for every row above; paths and symbol locations were read in this
working tree, not assumed from prior reports.

## 3. Current execution sequence (verified)

The exact order inside `DeploymentEngine.execute()` for a mixed Terraform+Kubernetes run:

| # | Event | Local/durable state at that moment |
|---|---|---|
| 1 | Pre-lease validation: execution enabled, store pre-read, resumable-state check, approval-hash match, effective-payload artifact hash match, namespace host-owned check | read-only; nothing persisted |
| 2 | `guard.acquire()` — unique owner token + monotonic fence; ExitStack registered (workspace disposal first, release second → LIFO release runs before workspace removal) | lease + active-fence keys live in Redis; fence counter advanced |
| 3 | Post-acquisition re-read; confirmed missing/terminal → discard approval workspace (only positively confirmed terminal); `_new_workspace("devops-exec-{id}-")`; `_write_iac` | run document unchanged |
| 4 | Defensive state advance to `DEPLOYING` + fenced `_commit` | **durable:** `DEPLOYING`, `execution` has no Kubernetes keys |
| 5 | `_verify_approved_plan_recoverable` (shared workspace intact, plan hash, credential profile) — local + filesystem checks | read-only |
| 6 | `terraform.initialize(..., before_operation=lambda: self._require_lease(guard))` | in-process ownership assertion immediately before sandbox launch |
| 7 | `terraform.apply_plan(..., before_operation=...)` | in-memory result; **not yet durable** |
| 8a | Terraform failed → `move(DEPLOYMENT_FAILED)` → `_rollback()` | `_rollback` first re-asserts ownership and fenced-commits `ROLLBACK_PENDING` (this is the first durable record of `terraform_apply`), **then** unconditionally calls `rollout_undo` for every parsed Deployment name |
| 8b | Terraform PASS → continue to Kubernetes | in-memory |
| 9 | `kubectl.apply(manifest, namespace, approved_identity, cancel_event, before_operation=lambda: self._require_lease(guard))`. Inside `KubectlRunnerService._execute`: (a) `_check_namespace`; (b) `_approved_manifest` — manifest policy evaluation, `manifest_sha256`, canonical YAML; (c) `_kubeconfig` — sanitize + CA fingerprint; (d) `execution_identity` — observed namespace/API/CA/profile/policy identity; (e) `verify_binding(approved, observed)` for mutating ops — **before** the sandbox is touched; (f) `build_kubectl_argv` + step policy validation; (g) `_resolve_sandbox`; (h) `before_operation()` — the last ownership assertion; (i) `sandbox.execute(...)` — network validation, private staging, network re-validation, container run with cancel/timeout kill; (j) result mapped to a payload dict | nothing durable; result exists only in the runner's return value |
| 10 | `run.execution["kubernetes_apply"] = kubernetes_apply`; `kubernetes_applied = status in (PASS, SKIPPED, NOT_APPLICABLE)` — **in memory** | durable record still says `DEPLOYING` with no Kubernetes keys |
| 11a | k8s failed → `move(DEPLOYMENT_FAILED)` → `_rollback()` (durable `ROLLBACK_PENDING` commit now also persists `kubernetes_apply`) | durable |
| 11b | k8s PASS → `_require_lease`; `move(HEALTH_CHECKING)`; fenced `_commit` — **first durable record of the apply result** | durable |
| 12 | `health_checker.check(...)` — `rollout_status` per Deployment name (read-only) + optional allowlisted HTTP GET | read-only |
| 13a | health FAIL → `move(DEPLOYMENT_FAILED)` → `_rollback()` | durable `ROLLBACK_PENDING` |
| 13b | health PASS → `move(DEPLOYED)` + fenced `_commit` | durable terminal |
| 14 | `finally`: `cleanup.close()` (release → then remove the per-execution workspace); `if run.state in _TERMINAL_STATES: self._discard_approval_workspace(run.id)` — **shared workspace deleted on local terminal state, including `LEASE_LOST` from a rejected commit** | local filesystem |

`_rollback()` itself (verified, lines 575–634): re-assert ownership → `move(ROLLBACK_PENDING)` →
fenced commit → `for name in deployment_names: rollout_undo(name, namespace, approved_identity=
self._approved_kubernetes_identity(run), cancel_event, before_operation=(lambda: self._require_
lease(guard)))` → optional Terraform rollback (`run.execution["terraform_applied"]` true and
`previous_good_terraform_tf` non-empty; otherwise a BLOCKED "No previous known-good Terraform
configuration was supplied." component) → `failed = [r for r in results if status != "PASS"]` →
`run.rollback = {"status": "PASS" if not failed else "FAIL", "components": results}` →
`ROLLED_BACK` or `ROLLBACK_FAILED` → fenced commit.

### Answers to the mandated sequence questions

1. **Approved manifest validated** — at apply time, before anything else, by
   `KubectlRunnerService._approved_manifest()` (manifest policy evaluate; the canonical YAML and
   `manifest_sha256` come from this evaluation). Also validated at dry-run time. **[Verified]**
2. **Target cluster identity verified** — `_execute` derives the observed identity from the
   sanitized kubeconfig and compares it to `run.execution["kubernetes_execution_identity"]` via
   `verify_binding` for `MUTATING_OPERATIONS` (APPLY, ROLLOUT_UNDO) — before the sandbox exists.
   This binds namespace/API-server/CA/profile/policy identities, **not** any per-resource cluster
   state. **[Verified]**
3. **Sandbox resolved** — after argv construction, before `before_operation`. **[Verified]**
4. **`before_operation` executes** — after all local policy/configuration work and immediately
   before `sandbox.execute()`. It is a pure in-process authorization callback: it persists nothing.
   **[Verified]**
5. **`sandbox.execute()` begins** — inside `ContainerKubectlSandbox.execute()` after network
   validation and private staging (network is re-validated immediately before launch).
   **[Verified]**
6. **Result durable** — only at the next fenced `_commit` after the sandbox returns
   (`ROLLBACK_PENDING` on failure, `HEALTH_CHECKING` on success). **[Verified]**
7. **Process death between any two events** — see §4.

### Is `before_operation` the correct durable operation-handoff boundary?

No. **[Engineering recommendation, grounded in verified source]** `before_operation` is an
authorization *assertion* (P1-3), not a *record*. A successful invocation proves only that the
worker still owned the lease at that instant; it proves nothing about what Kubernetes did, and it
leaves no durable trace. A successful local validation is not a provider-side operation, and a
callback invocation is not evidence that Kubernetes committed anything — it establishes at most
that the operation was about to be handed to the sandbox. The durable handoff boundary must be a
persisted record written **before** `sandbox.execute()` is called (§5).

## 4. Failure-window analysis

Death/failure between consecutive events of §3, with the current candidate's behavior:

| Window | Durable record after the event | Consequence today |
|---|---|---|
| Worker killed before handoff (before event 9h) | `DEPLOYING`, no k8s keys | Redelivery resumes; apply re-executed idempotently. Kubernetes never touched. Rollback (if reached) currently undoes anyway — the root-cause defect. |
| Worker killed after durable intent but before sandbox invocation | `DEPLOYING`, no per-operation intent exists (event 4 is the only durable point, and it precedes *all* operations) | Same as above — indistinguishable from "never attempted". |
| Worker killed during sandbox execution | `DEPLOYING` | The kubectl container may have applied some or all documents before the kill; no durable trace. Redelivery re-applies (safe for SSA apply per-object), but rollback evidence is lost. |
| Worker killed after sandbox returned, before next `_commit` | `DEPLOYING` | The apply result exists only in memory; a FAIL/TIMEOUT result is lost. Resumed worker re-executes from Terraform. |
| Worker killed after result commit, during health check | `HEALTH_CHECKING` + `kubernetes_apply` | Durable evidence exists; redelivery continues at health check. |
| Sandbox timeout (`OPERATION_TIMEOUTS[APPLY]=300s`, wall-clock kill, exit 124) | result status `TIMEOUT` if the worker survives to commit | TIMEOUT ≠ proven no-op: the API server may have accepted the request before the process was killed. Currently `kubernetes_applied=False` → rollback proceeds (undo), which is safe-direction for mutation, but the *evidence* is ambiguous and not durable until commit. |
| Sandbox cancellation (lease lost → `cancel_event` set; exit 130) | result status `CANCELLED` if committed at all | Same ambiguity; the process may have been killed mid-request. |
| Non-zero kubectl exit | result status `FAIL` | Same as TIMEOUT: FAIL means the command failed, not that Kubernetes did nothing (multi-document partial application). |
| Redis failure before attempt persistence | nothing | With the current code the apply is *not* gated on persisting an attempt record, so the handoff still occurs — an untracked provider operation. **This is the gap the evidence protocol must close (fail closed).** |
| Lease loss before operation authorization | `assert_owned()` raises → `LeaseLostDuringExecutionError` → LEASE_LOST path | No operation starts. Safe. |
| Lease loss after attempt persistence | attempt record durable (if protocol added) | Stale worker cancels and stops; new owner resumes; the attempt record must survive (monotonic). Today nothing is persisted, so nothing survives. |
| Result commit failure after Kubernetes may have changed state | fenced commit rejected (False) × `_COMMIT_RETRIES` → `LeaseLostDuringExecutionError` | The in-memory result is dropped; durable record stays `DEPLOYING`; resumed owner re-applies. Acceptable for apply (idempotent), but the *failure* result is lost, which matters for rollback decisions. |
| Redelivery/resumption by a new lease owner | `resumed_in_flight` → RECOVERING log → re-execute from Terraform | Idempotent by design for apply; but rollback decisions after re-execution have no memory of the *previous* worker's attempts. |
| Repeated attempts for one deployment run | every handoff must append, never overwrite | Today there is no attempt list; `kubernetes_apply` is overwritten by the latest attempt only. |

**[Verified in local source]** for all current-behavior cells.

Key inference: **a durable per-operation intent record and a monotonic mutated-fact are
required; a callback is not a boundary, and `kubernetes_applied == False` cannot distinguish
"not attempted" from "attempted and failed".** This matches the P2 review's finding and the P1-2
lesson that a state flag alone (`may_have_been_published`) proved insufficient without a
journal — but see §5 for why the *dispatch* journal's fence-independence rationale does *not*
transfer to apply attempts.

## 5. Durable evidence-model alternatives

### Conceptual evidence states (evaluated)

| State | Meaning | Use |
|---|---|---|
| `NOT_APPLICABLE` | manifest declares no Kubernetes component | already exists as a runner status (`_kubernetes_not_applicable`); keep **[Verified]** |
| `NOT_ATTEMPTED` | durable protocol evidence proves no handoff was ever made for this run's Kubernetes leg | legal **only** for runs created under the new protocol (a record with schema_version and zero attempts); must never be inferred from a missing field on a legacy record |
| `HANDOFF_PENDING` | intent durably persisted before sandbox invocation; the sandbox may or may not have been invoked (crash window) | treated as *may have mutated* |
| `RESULT_RECORDED` | terminal outcome recorded (status/exit code); `may_have_mutated` remains true | terminal per-attempt state |
| `LEGACY_UNKNOWN` | record predates the protocol (no schema version) | treated as *may have mutated* for rollback gating; labeled for audit; never downgraded to `NOT_ATTEMPTED` |

**[Engineering recommendation]** Adopt exactly these five; do not conflate "callback ran" with
"HANDOFF_PENDING" (a callback is not durable) or "FAIL result" with "NOT_ATTEMPTED" (a failed
provider call may still have mutated the cluster).

### Proposed versioned attempt record

```jsonc
{
  "schema_version": 1,
  "attempt_id": "uuid4",
  "operation": "apply",                      // "apply" | "rollout_undo"
  "manifest_sha256": "<approved canonical manifest digest>",
  "namespace": "devops-production-namespace",
  "resources": [{"apiVersion": "apps/v1", "kind": "Deployment", "name": "demo"}],
  "approved_identity_digest": "<KubernetesExecutionIdentity.digest()>",   // provenance only, no secrets
  "handed_off_at": "<ISO-8601 UTC>",
  "state": "HANDOFF_PENDING",                // -> RESULT_RECORDED
  "result": {"status": "FAIL", "exit_code": 1, "timed_out": false, "cancelled": false} | null,
  "may_have_mutated": true                   // monotonic per attempt; set at handoff, never cleared
}
```

Plus two scalar facts on `run.execution` that survive bounded-list truncation:

- `kubernetes_may_have_mutated: bool` — monotonic for the whole run; set true when any attempt is
  handed off (or at handoff-attempt persistence time); **never** cleared by a later unsuccessful
  retry. This is the direct analogue of P1-2's `may_have_been_published` fact.
- Bounded history: `kubernetes_operation_attempts` capped (recommendation: keep the last 8
  attempts); older entries may be dropped only because the scalar fact and every surviving
  attempt preserve the monotonic truth. **[Engineering recommendation]**

Persistence sequencing per attempt (fail-closed, mirroring P1-2's "an untracked publish must not
be made"):

1. Build the attempt record; persist it (`state=HANDOFF_PENDING`) via the normal fenced
   whole-document commit. If persistence fails → **do not call `sandbox.execute()`**; treat as an
   execution failure (no handoff, no mutation).
2. Call `sandbox.execute()`.
3. On return: set `result`, ensure `may_have_mutated=true`, persist via the next fenced commit.
   A FAIL/TIMEOUT/CANCELLED result still sets `may_have_mutated=true` — a failed command is not
   proof of a no-op.
4. Crash between 1 and 3 → the durable `HANDOFF_PENDING` entry remains; resumption treats it as
   *may have mutated*; a later successful retry **never erases it**.

Fencing interactions: the attempt write is a worker fenced commit; a stale worker's attempt write
is rejected by the fence (correct — a stale worker must not hand off anyway, and `_require_lease`
fires first). Redis failure before persistence → no handoff (fail closed). Lease loss after
persistence → the record stands; the new owner resumes and may append another attempt.

### Where to store: `run.execution` list vs separate Redis journal

| | `run.execution` bounded attempt list (recommended) | Separate Redis journal hash (P1-2 style) |
|---|---|---|
| Consistency | atomic whole-document fenced commit; attempt list + scalar fact always mutually consistent | second key surface; must reason about its own TTL/eviction and about its absence on legacy runs |
| Fence semantics | writes are fence-guarded — correct, because the only legitimate writer of an apply attempt is the current fence owner | the dispatch journal exists because an *API-side* writer raced a fast worker's fence; **that race does not exist here**: only the fence owner launches the sandbox |
| Visibility | visible in run inspection/API for free | requires extra read path |
| Growth | bounded by cap | unbounded unless TTL/limit added |
| Crash atomicity | single `SET` in `COMMIT_SCRIPT` — atomic | HSET per entry — atomic per entry but not grouped with document state |

**[Engineering recommendation]** Keep attempt evidence **inside `run.execution`**, persisted by
the same fenced commit — not a separate Redis journal. The P1-2 journal was justified by a
specific concurrency defect (an API writer whose run-document write was fence-blocked while the
journal key was not); the Kubernetes apply writer *is* the fence owner, so that justification
does not transfer. Introducing a second journal would add a consistency surface without closing a
demonstrated race. If a future change lets a non-owner persist attempt evidence, that decision
should be revisited with its own race analysis.

### Legacy compatibility

Existing in-flight `DEPLOYING`/`HEALTH_CHECKING` records created before the protocol carry no
attempt evidence. A missing evidence field must **not** be read as `NOT_ATTEMPTED`.
**[Engineering recommendation]** For a legacy in-flight record whose manifest declares
Kubernetes, set the effective fact to `LEGACY_UNKNOWN` → *may have mutated = true* for rollback
gating, with an explicit log/evidence marker. Rationale: the only way such a run reached
`DEPLOYING` is through the pre-apply commit, so the previous worker may have handed the apply off;
assuming not-mutated would leave a genuinely-broken workload un-rolled-back, while assuming
mutated bounds the damage of an unnecessary undo (the undo targets the manifest's own deployment
names; a deployment with no rollback target fails its component instead of silently deleting
anything — see §7 caveat). The stricter alternative (block automatic rollback on `LEGACY_UNKNOWN`
and require operator decision) is defensible and should be recorded as a deliberate choice at
implementation review; this document recommends the permissive-but-labeled variant so legacy
resumptions keep today's rollback capability without today's false "not attempted" reasoning.

## 6. Recommended state machine and outcome truthfulness

Verified current behavior:

- `_rollback` computes `failed` over `results`; **empty `results` ⇒ `status="PASS"` ⇒ `ROLLED_
  BACK`.** Concrete reachable case: a Terraform-declared payload with no Deployment in the
  manifest (or no Kubernetes at all) whose Terraform apply fails → `_rollback` with
  `deployment_names == []` and `terraform_applied == False` → zero components → `ROLLED_BACK`
  with nothing rolled back. A second case: a Kubernetes-only manifest of Service+ConfigMap (no
  Deployment) fails health check (empty check list ⇒ "No deterministic health signal was
  configured." ⇒ FAIL) → `_rollback` runs, no deployment to undo, `terraform_applied` is True
  (NOT_APPLICABLE counts as applied) and `previous_good_terraform_tf` is empty ⇒ one BLOCKED
  terraform component ⇒ `ROLLBACK_FAILED` with a misleading component. **[Verified in local
  source]**
- Transition table: `DEPLOYMENT_FAILED → {ROLLBACK_PENDING, LEASE_LOST}`;
  `ROLLBACK_PENDING → {ROLLED_BACK, ROLLBACK_FAILED, LEASE_LOST}`; `ROLLBACK_FAILED →
  {ROLLBACK_PENDING}`; `LEASE_LOST` terminal. **[Verified]**

**[Engineering recommendation]** Truthful **rollback metadata**, no new state transitions:

- Do not enter `ROLLBACK_PENDING` at all when durable evidence proves there is nothing to
  compensate; record `run.rollback = {"status": "NOT_REQUIRED", "reason": …}` and stay in
  `DEPLOYMENT_FAILED` (existing transition `DEPLOYMENT_FAILED` terminal-ward is fine; the run
  simply does not move to `ROLLBACK_PENDING`).
- Extend `run.rollback` to:
  `{"status": "PASS" | "PARTIAL" | "FAIL" | "NOT_REQUIRED" | "BLOCKED", "components": [...],
  "covered_resources": [...], "uncompensated_resources": [...], "evidence": [attempt_ids]}`.
  Each component carries `coverage` (e.g. `pod-template-only`) and, for kinds the rollback
  method cannot restore, `NOT_COMPENSATED`.
- Report `ROLLED_BACK` **only** when every declared resource that needed compensation is covered
  by a passing component. Anything else ⇒ `ROLLBACK_FAILED` (existing state) with
  `status: "PARTIAL"` metadata describing exactly what was and was not restored. A run with no
  external Kubernetes side effects must never be `ROLLED_BACK`.
- No new transitions are proposed; therefore no new transition-regression requirement is
  triggered. If reviewers prefer a first-class `ROLLBACK_PARTIAL` state, that is an explicit
  follow-up requiring: table change, `DEPLOYMENT_FAILED→ROLLBACK_PENDING→ROLLBACK_PARTIAL`
  edges, consumer/API mapping audit, and transition-table unit tests — recommended **not** to do
  now, to keep this change narrowly scoped.

## 7. Kubernetes revision and ownership analysis

**Verified command.** `build_kubectl_argv(KubectlOperation.ROLLOUT_UNDO, …)` returns
`("kubectl", "rollout", "undo", "deployment/<name>", "-n", <namespace>)` — no `--to-revision`.
**[Verified in local source]** (`kubectl_sandbox.py` lines 155–160). The runner's `rollout_undo()`
passes no revision parameter. **[Verified in local source]** (`kubectl_runner.py` 362–380).

**Official facts (kubectl v1.31.4-era reference; the repo pins kubectl v1.31.4 in
`e2e/pinned-kubectl.txt`):**

1. `--to-revision int` — "The revision to rollback to. Default to 0 (last revision)"; example
   `kubectl rollout undo deployment/abc` is documented as "Roll back to the previous deployment".
   So the current unpinned command targets the **last revision of that Deployment's own
   history**, whatever produced it. **[Official external documentation]**
2. A Deployment revision is created **if and only if** `.spec.template` changes; scaling and most
   other updates create no revision. **[Official external documentation]**
3. "When you roll back to an earlier revision, **only the Deployment's Pod template part** is
   rolled back." **[Official external documentation]**
4. "Each rollback updates the revision of the Deployment" — a rollback itself creates a new
   revision. **[Official external documentation]**
5. `.spec.revisionHistoryLimit` (default 10) garbage-collects old ReplicaSets; setting it to 0
   means the Deployment "will not be able to roll back". Cleanup starts only after the Deployment
   reaches a complete state; crash-looping deployments can exceed the limit. **[Official
   external documentation]**
6. The controller adds the `pod-template-hash` label to every ReplicaSet it creates or adopts;
   the current revision is visible as the `deployment.kubernetes.io/revision` annotation.
   **[Official external documentation]**
7. Object identity/concurrency: `UID` "uniquely identifies the object"; `PUT` requires the
   client-supplied `resourceVersion`, and a stale value yields `409 Conflict` — the API's
   conditional-update primitive. JSON Patch includes a test-op for consistency checks. Kubernetes
   verbs support **single resources only** — "no support for submitting multiple resources
   together in an ordered or unordered list or transaction". Dry-run requests are guaranteed to
   have no side effects. **[Official external documentation]**
8. Server-Side Apply records `managedFields`; changing a field another manager owns yields a
   **conflict**; resolving it by `force` overwrites the value and transfers ownership (never an
   acceptable *automatic* recovery action). The repository's apply pins
   `--field-manager=ares --server-side`. **[Official external documentation]** + **[Verified in
   local source]** (`FIELD_MANAGER`).

**Derived analysis (labeled):**

- **Default undo is not bound to this run.** It is bound to the target Deployment's revision
  history pointer. An external operator's change to `.spec.template` creates a new revision and
  moves what "last revision" means; the undo may then restore the operator's revision, not this
  run's pre-apply state. **[Unverified hypothesis at kubectl-implementation level, but directly
  implied by the official revision semantics above.]**
- **Newly created Deployment:** this run's apply is the *first* revision; there is no previous
  revision to roll back to. Unpinned undo on such a Deployment has no prior target; the precise
  kubectl error behavior is **[Unverified hypothesis]** (expected: a component failure, not a
  deletion). Creation rollback would require deletion, which the sandbox policy forbids
  (`delete` ∈ `FORBIDDEN_SUBCOMMANDS`). **[Verified in local source]**
- **Pruned history:** if the relevant revision's ReplicaSet has been garbage-collected, an undo
  targeting it fails; exact message **[Unverified hypothesis]**.
- **Ownership evidence available on the cluster:** UID (exact object identity),
  `metadata.resourceVersion` (optimistic-concurrency guard), `metadata.generation`
  (spec-change counter), `deployment.kubernetes.io/revision` annotation, `pod-template-hash` on
  ReplicaSets. A pre-apply capture of (UID, resourceVersion, generation, revision annotation) per
  Deployment would let a later compensator prove "the object this run changed is still the object
  I captured". None of this is captured today. **[Verified in local source]** (absence) +
  **[Official external documentation]** (semantics).
- **Conditional mutation inside the current closed policy: not expressible.** The policy admits
  exactly four operations; `get`, `patch`, `replace`, `scale` are unreachable, `-f` must reference
  exactly the manifest path, and `--server/--kubeconfig/...` flags are host-owned. A
  read-resourceVersion-then-conditional-PUT flow cannot be built without *widening the closed
  operation set* — a deliberate architecture decision with its own review. **[Verified in local
  source]**
- **Read-then-undo is not atomic.** Even with a GET added, a read followed by an unguarded undo
  has a check/use interval; Kubernetes provides no conditional `rollout undo`. **[Official
  external documentation]** (no conditional semantics on the command; single-resource verbs) +
  **[Engineering recommendation]** to state this limitation explicitly in code and docs.

### Required design alternatives

| | A. Gate existing undo on durable attempt evidence | B. Pre-apply identity/revision capture + pinned `--to-revision` | C. Capture pre-state, conditionally restore only if still owned | D. Block automatic rollback when ownership/revision cannot be established |
|---|---|---|---|---|
| Closes the root cause (undo after never-attempted apply) | Yes | Yes (as a side effect of capture) | Yes | Yes |
| Protects against operator-created revisions | No — undo still targets "last revision" | Partially — pins a revision, but the operator can still add revisions after capture; pinned target may be pruned | Best — restores only when the object is demonstrably still ours | Yes (refuses) |
| Restores Service/ConfigMap | No | No | Not without desired-state machinery | N/A |
| New sandbox operations required | None | A read-only `get` operation + `--to-revision` argv extension | Read + conditional write (patch/replace) — currently forbidden subcommands | None |
| Risk | Undo may target a wrong-but-real revision | Wider policy surface; capture may fail (then what?) | Complex; force-conflict temptation; not atomic anyway | False "nothing rolled back" when evidence is merely lost (mitigated by monotonic evidence) |
| Scope | Minimal; engine+runner evidence only | Engine + runner + sandbox policy + E2E | Effectively a compensation subsystem | Small |

**[Engineering recommendation]** **A + D** for the immediate task: durable attempt evidence gates
the undo; when evidence does not prove handoff (fresh protocol runs), the rollback records a
truthful non-compensation and does not call the cluster; legacy in-flight runs follow the §5
legacy rule. Explicitly record that `kubectl rollout undo` — pinned or not — cannot provide
conditional semantics; a read followed by an unguarded undo is not atomic and must never be
presented as such. B's capture machinery, the SSA-`ares` restoration idea (re-applying the
previous approved manifest under manager `ares`, refusing all conflicts, never
`--force-conflicts`), and Service/ConfigMap/created-resource restoration belong to the separately
scoped **compensation subsystem** (§11). Re-applying a prior manifest through SSA only restores
fields `ares` manages; conflicts with other managers must fail, and force-overwriting another
manager's fields is prohibited as an automatic recovery strategy. **[Engineering
recommendation, grounded in official SSA conflict semantics]**

## 8. Multi-resource rollback limitations

**[Verified in local source]**

- `DEFAULT_ALLOWED_RESOURCES = (("apps/v1","Deployment"), ("v1","Service"), ("v1","ConfigMap"))`;
  operators may widen via `DEPLOYMENT_K8S_ALLOWED_RESOURCES` (hard denies still apply). A wide
  operator configuration therefore admits kinds the rollback code has never handled.
- `_deployment_names()` parses **every** `kind: Deployment` document from the submitted YAML —
  including documents a manifest-policy BLOCK would have refused — and `_rollback()` undoes every
  one of them, regardless of which documents the (single) `kubectl apply -f` step actually
  reached. A partial multi-document apply (the API has no multi-resource transaction) can leave
  earlier documents applied while later ones failed; the current code treats all-or-nothing.
- `KubectlRunnerService.apply` reports `applied_resources` from the policy result, but no
  consumer maps it back to per-resource compensation.
- Rollout undo restores only Deployment pod templates (official docs, §7). Services' `spec`,
  ConfigMaps' `data`, and any resources **created** by this run are never compensated; deletion is
  forbidden by the sandbox policy; Terraform rollback covers only Terraform-managed state.

**[Engineering recommendation]** Smallest correct immediate scope: evidence-gated **Deployment
pod-template undo only**, with the rollback result truthfully scoped — components tagged
`coverage: "pod-template-only"`, uncovered kinds recorded as `NOT_COMPENSATED`, overall status
`PARTIAL` when any declared resource kind is not compensable, and `NOT_REQUIRED` when no
compensation is needed. Do **not** claim full-manifest rollback anywhere (state name, log line,
API docs). Service restoration, ConfigMap restoration, creation rollback, and any conditional
restore are an explicitly separated **compensation subsystem** follow-up (§11). A
`DEPLOYMENT_K8S_ALLOWED_RESOURCES` widening beyond the default trio should be flagged at
execution time as "rollback coverage not implemented for kind X" in the run's evidence.

## 9. Stale-worker cleanup findings (mandatory review)

**Scenario trace, verified against the current candidate:**

1. Worker A executes under lease/fence F_A. Its lease expires or is revoked; watchdog grace ends.
2. Worker B acquires a newer lease/fence F_B (higher monotonic token) and resumes the run from
   the persisted document; `tf_workspace = run.terraform_plan["approval_workspace"]` points at the
   **shared** `approved-{run_id}` directory created once at approval time by
   `_approval_workspace(run_id)`. **[Verified]** (paths: lines 336–366, 1125)
3. A's next ownership assertion (`_require_lease` → `assert_owned`) fails; the run takes the
   lease-loss path: `_handle_lease_loss` → `_mark_lease_lost` → `run.move(LEASE_LOST)` (local)
   → `guard.commit(...)` — **the commit's return value is ignored** (line 714), so a REJECTED
   commit (B's fence is active; `COMMIT_SCRIPT` compares `active_fence != F_A` → returns 0)
   leaves A with a local `LEASE_LOST` state while the durable record still says `DEPLOYING`
   under B. **[Verified]**
4. A returns through the `finally` (line 1291): `cleanup.close()` (release = stale no-op;
   removes A's own `devops-exec-…` workspace — safe), then
   `if run.state in _TERMINAL_STATES: self._discard_approval_workspace(run.id)` — and
   `LEASE_LOST ∈ _TERMINAL_STATES`. `_discard_approval_workspace` does
   `shutil.rmtree(base / f"approved-{run_id}")` — **the shared workspace B depends on**.
   **[Verified]**
5. B's `_verify_approved_plan_recoverable` then finds `Path(workspace).is_dir() == False`
   ("The approved plan workspace no longer exists") → B fails the run (`DEPLOYMENT_FAILED`) →
   B may even enter rollback for a run whose worker was healthy. **[Verified]** (lines 523–544)

The same discard also fires from the nested P2-B paths (`test_generic_recovery_…` scenarios end
in `_handle_lease_loss` → local LEASE_LOST → finally discard) and from `_mark_lease_lost` after
`ROLLBACK_FAILED` (the `move` raises, is swallowed, state stays `ROLLBACK_FAILED` — still
terminal → discard). **[Verified]**

**Differentiation of workspaces.** The **per-worker execution workspace**
(`_new_workspace("devops-exec-{run.id}-")`, created inside `execute()`, registered on A's own
ExitStack) is A-private and may be deleted by A at any time. The **shared per-run approval
workspace** (`approved-{run_id}`, created at approval, referenced by the persisted
`approval_workspace` path) must outlive any single worker and may be destroyed only when the run
is **positively terminal in the durable record** — which is exactly the rule the P2 candidate
implemented for the *setup* re-read but not for the *execution finally*. **[Verified]**

**On LIFO ordering.** `cleanup.close()` runs release-before-workspace-removal by construction,
but the approval-workspace discard is **outside** the ExitStack, keyed on A's *local* state, and
unconditional on fencing; `release()` being a compare-and-delete no-op for a stale owner provides
no protection whatsoever. **[Verified]** — release-before-deletion is *not* the safeguard here;
durable terminality is.

**Deterministic two-owner regression test (design).**

*Live-Redis variant (extends the `test_10/11` pattern in `test_execution_lease.py`):*
real store, real guards. A acquires, advances the run to `DEPLOYING` with the approved workspace
present, pauses at an injected pre-apply boundary. B acquires a strictly higher fence and commits
a newer state. A resumes: its assertion refuses; A's engine takes the lease-loss path; **assert
after A returns:** (i) `approved-{run_id}` still exists; (ii) the saved plan artifact inside still
hashes to the approved hash; (iii) A's own `devops-exec-…` directory is gone; (iv) B's persisted
document is unchanged; (v) B can subsequently complete `_verify_approved_plan_recoverable`
successfully.

*Unit variant (`test_deployment_engine.py`, FakeLeaseGuard):* B "owns" per the fake; force A's
`_mark_lease_lost` commit to be rejected (fake `commit` → False); assert the shared workspace
survives and only A's execution workspace is removed.

**[Engineering recommendation]** The implementation must gate the finally-discard on
fencing-confirmed terminality: discard only when the guarded commit that recorded the terminal
state **succeeded** (or when a fresh durable re-read positively confirms a terminal state), never
merely because the local object says terminal after a rejected commit.

## 10. Recommended minimal implementation scope

1. **Evidence protocol** (engine + runner seam): versioned attempt record in `run.execution`
   (schema per §5), persisted before sandbox handoff via the fenced commit; fail closed when
   persistence fails; result recorded and `may_have_mutated` made monotonic on return; bounded
   attempt history plus a run-scalar monotonic fact.
2. **Rollback gating** (engine `_rollback`): per Deployment name, undo only when durable evidence
   proves the apply attempt for the containing manifest was handed off (attempt with
   `may_have_mutated`), else record a truthful non-compensation component and do not call the
   cluster; legacy rule per §5; `NOT_REQUIRED` short-circuit when nothing needs compensation.
3. **Truthful rollback result** (engine): rollback status/metadata per §6; `ROLLED_BACK` only for
   complete, passing compensation; `PARTIAL`/`NOT_COMPENSATED` metadata otherwise; no new state
   transitions.
4. **Stale-worker workspace fix** (engine): gate the finally approval-workspace discard on
   fencing-confirmed terminality (§9 recommendation); add the two-owner regression tests.
5. **Tests**: the §12 matrix; extend existing suites, no new CI jobs required (live-Redis tests
   join the existing `redis-integration` steps so `runtime_guard`'s contract keeps matching).
6. **Docs**: truthful wording for `ROLLED_BACK`/`PARTIAL` in API/docs surfaces that mention
   rollback (run inspection fields), plus this document's decisions carried into
   `PROJECT_STATE.md`.

Explicit non-goals for the immediate change: no new kubectl operations, no `--to-revision`
plumbing, no pre-apply cluster capture, no Service/ConfigMap/creation compensation, no
SSA-restore subsystem, no Redis journal for attempts, no CI topology changes.

## 11. Explicit out-of-scope follow-ups (recommended, in order)

1. **Compensation subsystem** (separately scoped): pre-apply per-Deployment capture (UID,
   resourceVersion, generation, revision annotation), pinned `--to-revision` argv extension +
   read-only `get` operation, operator-revision/pruned-history handling, Service/ConfigMap
   restore, creation rollback, SSA-`ares` conditional restoration (never force-conflicts).
2. **`DEPLOYMENT_K8S_ALLOWED_RESOURCES` widening guard:** refuse or downgrade rollback coverage
   claims for operator-added kinds at execution time.
3. **First-class `ROLLBACK_PARTIAL` state** (only if metadata proves insufficient for consumers).
4. **Broker/provider-level fencing** remains a documented P1-3 boundary; unchanged.
5. **Legacy backfill tooling** for runs created before the protocol, if operations requires it.

## 12. Detailed regression-test matrix

Unit tests (no Redis; run in `security-integrity` / `kubernetes-trust-boundary` jobs with the
standard fakes; POSIX-only asserts need the documented Windows shim/skip discipline):

| # | Scenario (from task §8) | Design | Level |
|---|---|---|---|
| 1 | Terraform failure before Kubernetes: no undo | Payload declares k8s with 1 Deployment; fake terraform apply → FAIL; assert `kubectl.undo_calls == []`; rollback result has a Kubernetes component with `NOT_ATTEMPTED`/non-compensated truth, not an undo result | unit |
| 2 | Manifest-policy failure before handoff: no undo | Manifest the policy BLOCKs (e.g. denied volume type); `_deployment_names` still parses the name; assert no undo call and truthful component | unit |
| 3 | Kubeconfig/cluster-identity failure before handoff: no undo | Runner `_execute` returns BLOCKED at kubeconfig/identity stage; engine records FAIL; assert undo gated off (evidence: no handed-off attempt) | unit |
| 4 | Apply enters sandbox and returns FAIL: evidence remains may-have-mutated | Fake sandbox returns FAIL; assert the attempt record persisted by the next commit has `may_have_mutated=true`, `state=RESULT_RECORDED`, status FAIL; undo IS permitted for that target | unit |
| 5 | Apply timeout: evidence ambiguous | Fake sandbox `timed_out=True`; assert attempt `may_have_mutated=true`, status TIMEOUT; same gating as #4 | unit |
| 6 | Worker crash after intent commit, before sandbox result | Inject exception between handoff persistence and result recording; re-`from_dict` the persisted document; assert durable `HANDOFF_PENDING` attempt with `may_have_mutated=true` | unit |
| 7 | Worker crash during sandbox invocation | Same seam, exception inside `sandbox.execute`; identical durable assertions | unit |
| 8 | Result persistence failure after sandbox invocation | Fenced commit returns False at result recording; assert attempt stays `HANDOFF_PENDING`, mutated fact monotonic true | unit |
| 11 | Legacy in-flight record without new evidence | `DeploymentRun.from_dict` of a protocol-less `DEPLOYING` document; assert `LEGACY_UNKNOWN` semantics (undo permitted and labeled, never `NOT_ATTEMPTED`) | unit |
| 12 | Multiple Deployments in one manifest | Two-Deployment manifest; partial-apply simulation (first PASS, second FAIL at sandbox seam); assert per-deployment truthfulness and no blanket undo of unreached targets where evidence cannot prove handoff | unit |
| 13 | Deployment + Service + ConfigMap | Assert Service/ConfigMap recorded `NOT_COMPENSATED`, overall `PARTIAL`, state `ROLLBACK_FAILED` (metadata) or explicit non-`ROLLED_BACK` outcome | unit |
| 17 | No-rollback-required execution does not report ROLLED_BACK | Terraform-only payload, apply FAIL; assert `run.rollback.status == "NOT_REQUIRED"`, state stays `DEPLOYMENT_FAILED`, never `ROLLED_BACK`; second case: Service+ConfigMap-only manifest health failure does not report an empty-PASS rollback | unit |

Live-Redis tests (join the existing `redis-integration` steps so the structural guard's
recognized step list keeps matching; `REDIS_INTEGRATION_REQUIRED=true`, pinned Redis digest):

| # | Scenario | Design |
|---|---|---|
| 9 | Lease failure before marker persistence | Real guard; `assert_owned` outage at the handoff seam; assert no attempt persisted **and** no sandbox call |
| 10 | Lease loss during recovery | B supersedes A (higher fence); A's attempt write rejected; assert A's record not overwritten; B resumes and its own attempt evidence is the one persisted |
| 16 | Stale worker cannot remove successor's approval workspace | The §9 two-owner test, live-Redis variant, with all five assertions |
| 18 | Fenced Redis commits protect attempt evidence against stale owners | Stale worker's attempt-rewrite rejected by `COMMIT_SCRIPT`; monotonic mutated fact survives |

Kind E2E (existing `kubernetes-kind-e2e` / `kubernetes-service-http-e2e` jobs; pinned kubectl
v1.31.4 + pinned node image; driver extension only — not unit-simulatable):

| # | Scenario | Design |
|---|---|---|
| 14 | External operator creates a newer revision before recovery | Driver applies run manifest, applies an external template change (new revision), triggers failure path; assert the rollback either pins/blocks per chosen design and never restores the operator's revision silently |
| 15 | Revision history unavailable | Driver sets `revisionHistoryLimit: 0` (or prunes) before failure; assert rollback component FAILs truthfully instead of claiming success |

**[Engineering recommendation]** — this matrix is a design; no tests have been implemented or run
for it in this pass.

## 13. CI validation plan

- Local (this Windows checkout): shimmed focused engine selections only, with the documented
  `os.getuid/getgid` process-local shim; expect the known POSIX-path test failure to remain
  out-of-scope; **no result claims in advance**.
- Canonical validation happens in hosted CI at the implementation SHA (Python **3.11**;
  Windows-local Python 3.12.5 differences must not be reported as CI evidence):
  - `security-integrity`: full unit suite incl. new engine/runner tests; digest-pinned
    `redis:7.2-alpine@sha256:29e8589c…` service for dispatch-contract live tests (unchanged).
  - `redis-integration`: new live-Redis lease/evidence tests appended to the **existing** steps
    (keeping `runtime_guard._check_redis_integration_contract` matching), `REDIS_URL` +
    `REDIS_INTEGRATION_REQUIRED=true`.
  - `kubernetes-trust-boundary`: policy/argv unit tests (e.g. any new evidence-schema invariants
    that are static).
  - `kubernetes-kind-e2e` / `kubernetes-service-http-e2e`: scenarios 14–15 via driver extension;
    kubectl fetched against `e2e/pinned-kubectl.txt` (v1.31.4).
- `structural-guards` + `python -m security_guards` must stay green; no new CI jobs; no workflow
  edits required by the recommended scope.
- Mutation probes: add/extend probes only if reviewers request them; M-numbers continue from the
  existing registry.
- **Nothing may be claimed as passed before a hosted run at the exact implementation SHA.**
  **[Engineering recommendation]**

## 14. Remaining uncertainties

1. Exact kubectl v1.31.4 behavior (error text/exit codes) for `rollout undo` with no previous
   revision or a pruned target — needs a kind run or kubectl source inspection. **[Unverified
   hypothesis]**
2. Whether kubectl v1.31.4 `apply -f` with multiple documents stops at the first failing document
   or continues; determines partial-apply evidence granularity. **[Unverified hypothesis]**
3. Whether the Deployment controller's `DeploymentRollback` semantics create a new revision even
   when the target revision equals the current template (affects repeated undo idempotency).
   **[Unverified hypothesis]**
4. The exact boundary of `_COMMIT_RETRIES` (3 × 0.5 s) versus a Redis blip during attempt
   persistence — could a transient outage cause a *failed* handoff persistence and thus a
   legitimate no-handoff? Acceptable (fail closed) but worth an explicit ops note.
   **[Engineering recommendation]**
5. Bounded attempt-list cap size (8 suggested) — requires review against realistic attempt
   frequency (bounded retries inside the engine, watchdog cancels, redeliveries). **[Engineering
   recommendation]**
6. Whether any consumer of `run.rollback` (API inspection surfaces) keys on the current
   `{"status": PASS|FAIL}` shape and must be updated together. **[Unverified hypothesis —
   needs a consumer audit during implementation]**

## 15. External official references

All fetched 2026-11-14:

1. `kubectl rollout undo` reference — synopsis "Roll back to a previous rollout";
   `--to-revision int` "The revision to rollback to. Default to 0 (last revision)".
   https://kubernetes.io/docs/reference/kubectl/generated/kubectl_rollout/kubectl_rollout_undo/
2. Deployments concepts — revision created iff `.spec.template` changes; "only the Deployment's
   Pod template part is rolled back"; each rollback creates a revision; `revisionHistoryLimit`
   default 10, 0 disables rollback; `pod-template-hash` label; `deployment.kubernetes.io/revision`
   annotation.
   https://kubernetes.io/docs/concepts/workloads/controllers/deployment/
3. API concepts — `resourceVersion`/`409 Conflict` optimistic concurrency; JSON-Patch test-op;
   single-resource verbs only (no multi-object transaction); dry-run side-effect guarantee;
   UID uniqueness.
   https://kubernetes.io/docs/reference/using-api/api-concepts/
4. Server-Side Apply — managed fields, conflicts, `force` semantics (ownership transfer),
   field managers, ownership transfer between managers.
   https://kubernetes.io/docs/reference/using-api/server-side-apply/
5. Pinned tooling (local, committed): `devops-ai-platform/e2e/pinned-kubectl.txt` — kubectl
   **v1.31.4**, sha256 `298e19e9c6c17199011404278f0ff8168a7eca4217edad9097af577023a5620f`;
   CI also pins `redis:7.2-alpine@sha256:29e8589c3f9ba699b5f7aa4b3c7733c58852a3626439e619aa0ee78de08c6ca0`.

---

# Amendment (2026-11-14) — rollback authorization and recovery safety

This amendment supersedes only the recommendations it explicitly changes. In particular,
the earlier recommendation that `may_have_mutated` can gate automatic `rollout undo` is
withdrawn. It remains essential attempt evidence, but is not compensation authorization.

**Supersession rule for implementers.** This amendment overrides every earlier passage,
roadmap item, and regression-test row that says durable handoff evidence (including
`LEGACY_UNKNOWN`) permits automatic Deployment undo. In particular, do not implement the
earlier evidence-gated `rollout_undo` recommendation or its "undo is permitted" tests.
For P2.1, all Kubernetes compensation without current-resource authorization is blocked;
the prior material remains historical failure analysis only.

## A. Operation evidence is not rollback authorization

| Question | Durable fact required | Permits | Never implies |
| --- | --- | --- | --- |
| A. Did this execution potentially mutate Kubernetes? | A fenced attempt record was committed before sandbox handoff; `may_have_mutated` is monotonic. | Truthful incident/recovery reporting and conservative reconciliation. | That this run still owns or may safely change the live object. |
| B. Is this execution authorized to compensate the exact resource now observed? | Current-resource proof binds the intended object and recorded before/after provenance, plus an atomic conditional restoration mechanism. | Narrow compensation of that exact object. | That a prior sandbox handoff independently authorizes `kubectl rollout undo`. |

`may_have_mutated=true` answers A only. It says a request may have crossed the
external boundary; it cannot say which documents the API server accepted, whether a
same-name object was deleted and recreated, whether an operator has since changed the
object, or which revision is now safe to restore. Evidence is not a capability.

**Required P2.1 decision.** If A is true and B cannot be established, do not execute
automatic Kubernetes compensation. Preserve the evidence and record `BLOCKED` /
`OPERATOR_REQUIRED`; never report `ROLLED_BACK` or silently choose another revision.
For pre-protocol, in-flight documents, `LEGACY_UNKNOWN` is an operator-escalation reason,
not permission for undo. This preserves legacy inspection/resume compatibility while
removing the unsafe automatic action.

### Checked-in sandbox limitation

**[Verified local source.]** The closed operation set is `SERVER_SIDE_DRY_RUN`, `APPLY`,
`ROLLOUT_STATUS`, and `ROLLOUT_UNDO` (`application/services/kubectl_sandbox.py`). The
only current undo argv is:

```
kubectl rollout undo deployment/<approved-name> -n <host-owned-namespace>
```

There is no sandboxed `get`, controlled JSON-patch/update, expected UID/resourceVersion/
template input, or `--to-revision` plumbing. The default manifest allowlist is Deployment,
Service, and ConfigMap; `DEPLOYMENT_K8S_ALLOWED_RESOURCES` can widen it. Lease assertions
fence Redis ownership and starts, not Kubernetes object state.

**[Official external documentation.]** `rollout undo` rolls a Deployment to a previous
rollout (default `--to-revision=0` selects the then-current previous revision). Deployment
revisions concern `.spec.template` only; history may be pruned or disabled. Kubernetes
optimistic concurrency is object-scoped and does not make a caller's prior read and a
separate command a transaction.

This prohibited sequence explains the distinction:

```
worker reads D at T1 -> operator changes D at T2 -> worker runs rollout undo D at T3
```

The undo command cannot receive the T1 UID, post-apply template/revision, or resourceVersion
as an application-required precondition. Even if its internal API interaction sees an ordinary
conflict, it can read the operator's newer state and undo *that* current revision. A read
followed by ordinary undo is not atomic conditional authorization; do not claim otherwise.

### P2.2 provenance requirements

| Candidate fact | Purpose | Why it is insufficient alone / failure rule |
| --- | --- | --- |
| Namespace + name | Names expected object. | Delete/recreate can reuse it; UID mismatch blocks. |
| Object UID | Binds identity across reads. | Must still match; mismatch is `BLOCKED`. |
| Pre-apply template digest | Defines intended Deployment-template restoration. | Does not prove current template is ours. |
| Pre-apply revision / ReplicaSet | Identifies historical candidate. | May be absent/pruned; never substitute another revision. |
| Post-apply template digest + revision | Identifies the change this execution attempted/observed. | Missing/changed value blocks automatic restoration. |
| resourceVersion | Observed pre/post and final concurrency compare. | Any write, including controller status, can alter it; strict mismatch safely blocks. |
| generation | Detects spec evolution. | Not a complete concurrency guard. |
| External operator change | Detected by UID/RV/generation/template/revision mismatch. | Never overwrite; report `BLOCKED`. |

**[Engineering recommendation for P2.2.]** Add bounded read/capture plus a dedicated,
atomic conditional-write operation; do not expose a generic kubectl shell. The write must
test UID, resourceVersion, and exact expected post-apply template/revision projection in
the same API request before replacing only the approved pre-apply template (for example,
a generated JSON Patch with `test` operations). UID mismatch, 409/test failure, missing
history, or unrecognized state is `BLOCKED` / operator required. Never force conflicts.

## B. Stale-worker shared approval-workspace ownership

**[Verified local source.]** `approved-{run_id}` is a shared, durable per-run Terraform
approval workspace. `devops-exec-{run_id}-...` is the creating worker's private execution
workspace. Current `finally` deletes the shared path from A's in-memory terminal state
after `_mark_lease_lost()` ignores a rejected fenced commit. A can therefore delete B's
plan after B owns a newer fence.

| Workspace | Owner | Safe deletion rule |
| --- | --- | --- |
| `devops-exec-{run_id}-...` | Creating worker only | The creator may remove it in `finally`, even stale. |
| `approved-{run_id}` | Durable run, not a worker | Use the terminal-cleanup protocol below; local terminal state never suffices. |

Required protocol:

1. Retain the active lease and fence all state writes.
2. Commit the terminal result under that fence and record whether the commit succeeded.
3. Only a successful terminal fenced commit authorizes that same owner to remove the
   shared workspace, before it releases the lease. A rejected/failed/unknown commit
   authorizes no shared deletion.
4. Durable terminality is a terminal-run guard: later workers must refuse resumption. A
   recovery/reaper may delete only after a fresh successful durable re-read proves terminal;
   read error means retain.
5. Release the lease after deletion. Cleanup failure is observable safe retention.

No Redis-plus-filesystem atomic delete exists and a second journal does not solve that
cross-system gap. A successful fenced terminal commit plus the still-held active fence
is sufficient authorization; terminal state prevents a successor from resuming during a
crash between the commit and deletion.

```mermaid
sequenceDiagram
  participant A as Worker A / FA
  participant R as Redis run + fence
  participant FS as approved workspace
  participant B as Worker B / FB
  A->>R: stale terminal commit(FA, LEASE_LOST)
  B->>R: acquire newer FB; persist resumable record
  R-->>A: rejected (FA != active FB)
  Note over A,FS: A removes only its devops-exec workspace
  A--xFS: MUST NOT delete approved workspace
  B->>FS: verify plan; resume
  B->>R: terminal commit(FB) succeeds
  B->>FS: delete shared workspace while FB held
  B->>R: release(FB)
```

**P2.1 regression requirement.** Add a deterministic two-owner real-Redis test: A pauses
under F_A with a valid approved plan; B acquires F_B and persists newer resumable state;
A resumes, loses ownership, and its F_A commit is rejected. Assert the approved workspace
and its plan hash survive, A's private execution workspace is gone, B's document is
unchanged, and B passes `_verify_approved_plan_recoverable`. Add the equivalent rejected-
commit unit test. This is immediate P2.1 scope.

## C. v1.31.4 partial application and truthful outcomes

**[Verified local configuration.]** `e2e/pinned-kubectl.txt` pins Linux amd64 `kubectl
v1.31.4`, SHA-256 `298e19e9c6c17199011404278f0ff8168a7eca4217edad9097af577023a5620f`.
Both Kind jobs fetch and verify that value.

**[Verified version-specific upstream behavior.]** The matching Kubernetes source tag is
[`v1.31.4`](https://github.com/kubernetes/kubernetes/tree/v1.31.4), client commit
`a78aa47129b8539636eb86a9d00e31b2720fe06b`. Its
[`apply.go`](https://github.com/kubernetes/kubernetes/blob/v1.31.4/staging/src/k8s.io/kubectl/pkg/cmd/apply/apply.go)
uses `ContinueOnError`, retains valid objects alongside builder errors, loops
`applyOneObject` for every retained object, and returns one error or an aggregate after
the loop. Application is therefore sequential per object, continues after individual
errors, aggregates errors, and is not transactional. The tagged
[`rollout_undo.go`](https://github.com/kubernetes/kubernetes/blob/v1.31.4/staging/src/k8s.io/kubectl/pkg/cmd/rollout/rollout_undo.go)
provides ordinary previous-revision/`--to-revision` semantics, not caller-supplied UID,
resourceVersion, or template conditions.

A wholly malformed manifest or setup/validation failure before valid objects reach the
loop can happen without mutation. A mixed malformed/valid manifest can still apply valid
objects; an API failure for one object does not stop later ones. Earlier and later objects
may thus mutate despite the one nonzero process result. Current sandbox output is
invocation-level: policy `applied_resources` is declared resources, not individual API
acknowledgements; timeout/crash preserves partial-application uncertainty.

P2.1 consequently marks every declared resource in a handed-off invocation conservatively
`may_have_mutated=true`. It does not prove that each was reached. P2.2 read-before/read-
after provenance refines per-resource facts. `rollout undo` restores neither Service nor
ConfigMap nor resources newly created by the invocation; it only restores a Deployment
Pod template.

| Overall outcome | Meaning | Existing state mapping |
| --- | --- | --- |
| `COMPLETE` | Every required compensation completed and was verified. | `ROLLED_BACK`; only this may claim rolled back. |
| `PARTIAL` | Some verified restoration, but another required component is uncovered/unknown/incomplete. | `ROLLBACK_FAILED` with outcome details. |
| `BLOCKED` | Policy forbade action: missing authorization, legacy unknown, conflict, pruned history, or unavailable evidence. | `ROLLBACK_FAILED`, `operator_action_required=true`. |
| `FAILED` | Permitted compensation was attempted but failed or was unverified. | `ROLLBACK_FAILED`. |
| `NOT_REQUIRED` | No external mutation was handed off / no compensation required. | Stay `DEPLOYMENT_FAILED`; do not enter rollback. |

The current transition graph is sufficient only if P2.1 replaces binary `PASS|FAIL` rollback
metadata with a versioned outcome and components containing resource key, kind, evidence,
coverage, outcome/reason, and verification. The empty-component `PASS` defect must go.
No immediate new state is necessary: `ROLLED_BACK` is reserved for `COMPLETE`, and every
incomplete result is explicit to API consumers through `ROLLBACK_FAILED` metadata. A
dedicated partial state is needed later only if consumer audit shows metadata cannot be
consumed. Service/ConfigMap presence makes `COMPLETE` impossible in P2.1 after handoff.
An expanded allowlist must fail closed before mutation without explicit coverage policy.

## D. Bounded evidence retention

**[Verified local source.]** Manifest policy and its stored resource list are unbounded;
there is no Kubernetes attempt-history limit. The prior suggested cap of eight is unsafe
alone because it can discard a resource's only mutation evidence.

**[P2.1 engineering decision.]** Enforce, before execution: at most **32 canonical
resources** per invocation and **16 detailed attempt records** per run, plus a non-
evictable per-resource summary (one entry for each of at most 32 canonical
`apiVersion/kind/namespace/name` keys bound to the approved manifest hash) and non-
evictable run scalar `any_kubernetes_may_have_mutated`. These are new protocol limits,
not a claim that current source enforces them; they bound the existing 300-second single
sandbox invocation and the Redis run document where source currently provides no bound.

Compaction may remove diagnostic detail only after the same fenced run-document commit
merges it into the summary. Each summary preserves OR-only `may_have_mutated`, first/last
attempt IDs/times, manifest identity, and last result class. Missing summary means
**unknown**, never no mutation. If capacity/evidence persistence fails, retain existing
facts and fail closed before a new external mutation. Do not truncate or reset. A second
Redis journal is unnecessary: this bounded evidence belongs to the same fenced execution
record and must be atomically committed before handoff.

## E. Revised implementation boundaries

### P2.1 — immediate

1. Durable fenced Kubernetes attempt evidence; persist before sandbox execution; fail
   closed when persistence/capacity fails; monotonic uncertainty across crashes/retries.
2. Prevent rollback when Kubernetes was never reached; never automatically undo where
   current-resource authorization cannot be proven; retain evidence and report blocked.
3. Accurate `COMPLETE`/`PARTIAL`/`BLOCKED`/`FAILED`/`NOT_REQUIRED` reporting and legacy
   record compatibility; only verified `COMPLETE` reaches `ROLLED_BACK`.
4. Shared-workspace stale-worker correction and deterministic two-owner Redis regression.

P2.1 does not add a full compensation system: no pre-apply capture, get/patch capability,
`--to-revision`, Service/ConfigMap/create restoration, SSA force-conflict behavior, or CI
topology expansion.

### P2.2 — conditional compensation

Add resource identity/revision provenance, conditional restoration and external-operator
concurrency protection, partial-resource compensation, safe pruned-history handling, and
explicit operator intervention whenever safe restoration cannot be proven.

### P2.3 — integration acceptance

Validate with real Redis, Linux, Celery worker-loss/two-owner tests, Kubernetes/Kind and
pinned kubectl v1.31.4, concurrent operator mutation, hosted CI, and end-to-end recovery.

## F. Evidence classification and remaining uncertainty

| Classification | Amendment evidence |
| --- | --- |
| Verified local source | Allowlist/argv, no conditional mutation path, workspace race, current binary outcome/state graph, and absent resource/attempt caps. |
| Verified version-specific upstream behavior | v1.31.4 apply continuation/per-object aggregation and undo interface in §C. |
| Official external documentation | Deployment revision/template limits, undo options, API concurrency and JSON-patch semantics. |
| Engineering decisions | P2.1 no-auto-undo, retention limits/schema, cleanup protocol, outcome mapping, and roadmap. |
| Unresolved until P2.3 Kind proof | Exact server exit/output for pruned/no-prior revision, target-controller resourceVersion churn, and API-consumer audit. Each uncertainty maps to `BLOCKED`, never automatic undo. |

References: [v1.31.4 source tag](https://github.com/kubernetes/kubernetes/tree/v1.31.4),
[kubectl undo reference](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_rollout/kubectl_rollout_undo/),
[Deployment rollback scope](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/),
[API concepts](https://kubernetes.io/docs/reference/using-api/api-concepts/), and
[Server-Side Apply conflicts](https://kubernetes.io/docs/reference/using-api/server-side-apply/).

   `.github/workflows/ci.yml` — `redis:7.2-alpine@sha256:29e8589c3f9ba699b5f7aa4b3c7733c58852a3626439e619aa0ee78de08c6ca0`.
