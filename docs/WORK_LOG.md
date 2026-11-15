# Engineering work log

Append entries; do not rewrite historical findings. Results below describe local evidence only unless they explicitly cite a hosted run.

## 2026-11-14 — Phase 8.8A P2 recovery-safety review

**Objective.** Complete the P2-A execution-lease cleanup and P2-B nested lease-loss review, make only demonstrated corrections, validate the candidate, and establish durable project handoff documentation.

**Initial Git state.** `fix/p2-recovery-cleanup` at `72189146ceb3206a9ecd7a8734d26cac7ab16275`; `origin` fetch/push URL was `https://github.com/gm-prog/Autonomous-Devops-Engineer.git`. `e1d0040` and `b75cc30` were confirmed ancestors. Four unstaged changes already existed in the engine, engine tests, lease tests, and Phase 8.8A findings matrix; no staged/deleted/untracked paths were reported. The original checkout was read-only and reported `main...origin/main [behind 5]`.

**Review evidence.** Inspected the complete `DeploymentEngine.execute`, `_rollback`, `_commit`, `_require_lease`, `_mark_lease_lost`, `_handle_lease_loss`, approval/workspace helpers; the complete `ExecutionLeaseGuard.acquire/assert_owned/commit/release`; `DeploymentState` transitions; both generic-recovery tests; all candidate diffs; CI workflow jobs; deployment API/Celery task sources; container sandbox and trust-boundary test surfaces. State transitions `DEPLOYMENT_FAILED -> LEASE_LOST` and `ROLLBACK_PENDING -> LEASE_LOST` are present.

**Findings and correction.** The pre-existing candidate correctly registered cleanup immediately after acquisition and narrowly caught lease loss nested in generic recovery. One P2-A gap remained: a positively confirmed missing or terminal post-acquisition re-read raised from setup before the normal finalizer, leaving its single-use approval workspace. `execute()` now discards that workspace only for confirmed missing/terminal outcomes; store exceptions and awaiting-approval/nonterminal records retain it. `ExitStack` callback registration was reordered so LIFO closure releases/stops the guard before removing an existing execution workspace. Approval-workspace removal is best effort and cannot hide a primary `OSError`. Regression tests cover confirmed cleanup, uncertain-read preservation, and persisted newer-owner authority for both P2-B scenarios.

**Separate rollback finding (not patched).** Severity: high safety defect. `_rollback()` invokes `kubectl.rollout_undo` for every parsed deployment name before checking whether Kubernetes apply was attempted. `execute()` calls `_rollback()` when Terraform apply failed, so a Terraform failure before Kubernetes reaches the workload can mutate an untouched deployment. `kubernetes_applied == False` cannot distinguish not-attempted from attempted-and-failed, and resumed state may carry prior evidence. Required scope: separately define durable Kubernetes-attempt evidence and gate rollback undo; do not fold it into lease cleanup.

**Test ledger (working directory `devops-ai-platform` unless stated).**

- `python -c "import os, pytest; os.getuid=lambda: 1000; os.getgid=lambda: 1000; raise SystemExit(pytest.main(['deployment_service/tests/test_deployment_engine.py','-q','--no-header','-k','post_acquisition or workspace_setup']))"` — exit 0; 7 passed, 22 deselected. Process-local Windows compatibility shim only.
- `python -c "...pytest.main(['...::test_generic_recovery_lease_loss_at_rollback_entry_is_handled','...::test_generic_recovery_commit_lease_loss_is_handled','-q','--no-header'])"` — exit 0; 2 passed.
- Native focused P2-A selection — exit 1; 7 failed, 22 deselected because Windows lacks `os.getuid`/`os.getgid`.
- Full shimmed `test_deployment_engine.py` — exit 1; 28 passed, 1 failed. The failure asserts POSIX `/rollback/` in a Windows backslash path.
- `REDIS_INTEGRATION_REQUIRED=true python -m pytest deployment_service/tests/test_execution_lease.py -q --no-header` — test exit 1; 18 setup errors: no live Redis URL/server. No shared Redis flush was performed.
- Shimmed `test_deployment_api_dispatch_contract.py` first test — exit 1; configured `127.0.0.1:6399/1` refused connection after 28.82s. The full suite attempt did not return within its command window and its orphaned test process was stopped; it has no result.
- Shimmed `test_terraform_trust_boundary.py` — exit 1; 133 passed, 2 failed: Windows symlink privilege and absent `signal.SIGKILL`.
- Shimmed Kubernetes trust suite (`test_kubernetes_trust_boundary.py`, `test_sandbox_network_isolation.py`, `test_kubeconfig_staging_permissions.py`) — exit 0; 246 passed, 1 skipped: Linux-specific F4 permission semantics.
- `REDIS_INTEGRATION_REQUIRED=true python -m pytest tests/test_celery_crash_recovery.py -q --no-header` — test exit 1; 1 passed, 1 fail-closed live-Redis setup error.
- `python scripts/assert_no_host_terraform_execution.py` — exit 0; no host Terraform path found across 10 audited modules.
- Terraform mutation driver returned 0 but its copied probes said `No module named pytest`; this is invalid evidence. Kubernetes mutation driver had no result before command timeout. Neither is counted as passed.

**Environment.** Python 3.12.5 with pytest 9.1.1 and redis 8.1.0; CI pins Python 3.11. Docker CLI exists but Docker Desktop Linux daemon is unavailable. `redis-server`, `redis-cli`, and `kind` are absent. Java 23 is installed; Gradle was not run. Hosted CI is unverified because no new candidate SHA was pushed.

**Disposition.** Not ready for independent approval while the adjacent rollback-safety defect and required Linux/live-Redis validation remain. No commit, push, PR, merge, deployment, or main modification was made.

## 2026-11-14 — Phase 8.8A Kubernetes rollback-safety research (design only)

**Objective.** Research-only pass: establish the exact Kubernetes apply/rollback execution sequence, design a durable operation-provenance protocol, audit rollback safety, the stale-owner cleanup race, state-machine truthfulness, and produce an implementation-ready architecture decision. No feature implementation, no application/test/CI/infrastructure changes.

**Initial and final Git state.** `fix/p2-recovery-cleanup` at `72189146ceb3206a9ecd7a8734d26cac7ab16275` before and after. Four modified tracked files and five untracked documentation files at start (nine total, matching the previous report); the sixth untracked file (`docs/PHASE-8.8A-KUBERNETES-ROLLBACK-SAFETY-RESEARCH.md`) was created by this research, giving ten files at the end. `e1d0040` and `b75cc30` re-verified as ancestors via `git merge-base --is-ancestor` (both exit 0). Original checkout `C:\Users\deysa\Autonomous-Devops-Engineer` verified untouched and read-only: `main`, clean (0 modified), HEAD `64c77e9`.

**Verified sequence (source).** `DeploymentEngine.execute()` (lines 1022–1297): pre-lease validation → lease acquire + ExitStack → post-acquisition re-read → `DEPLOYING` fenced commit → Terraform verify/init/apply → on failure `_rollback()`; `KubectlRunnerService._execute()` (202–292): namespace check → manifest policy → kubeconfig sanitize → observed identity + `verify_binding` → argv/step policy → sandbox resolve → `before_operation()` → `sandbox.execute()` → result payload; `run.execution["kubernetes_apply"]` is written in memory after the sandbox returns and becomes durable only at the next fenced commit (`ROLLBACK_PENDING` on failure, `HEALTH_CHECKING` on success). No durable pre-handoff intent and no Kubernetes attempt journal exist; `before_operation` persists nothing and is not a handoff boundary.

**Root cause re-verified.** `_rollback()` (575–634) fenced-commits `ROLLBACK_PENDING`, then unconditionally calls `kubectl.rollout_undo` for every Deployment name parsed from the submitted manifest (`_deployment_names` parses raw YAML, including documents a manifest-policy BLOCK would refuse). It is reached after Terraform failure (1224–1228), Kubernetes apply failure (1246–1250), and health-check failure (1260–1264). `kubectl rollout undo` is emitted without `--to-revision` (`kubectl_sandbox.py` 155–160; runner passes none).

**New confirmed findings.**
1. Truthfulness defect: `_rollback` computes `failed` over `results`; empty `results` ⇒ `status PASS` ⇒ `ROLLED_BACK`. A Terraform-declared run with no Deployment in the manifest whose Terraform apply fails reports `ROLLED_BACK` with zero rollback components (names `[]`, `terraform_applied` false). A Service+ConfigMap-only manifest failing health check yields a misleading BLOCKED-Terraform `ROLLBACK_FAILED` instead of a truthful non-compensation.
2. Stale-owner workspace race confirmed in the current candidate: `_mark_lease_lost` (703–714) sets local `LEASE_LOST` ignoring the fenced commit's rejection; `execute()`'s `finally` (1291–1297) then calls `_discard_approval_workspace(run.id)` because `LEASE_LOST ∈ _TERMINAL_STATES`, deleting the shared `approved-{run_id}` workspace that worker B (higher fence, resuming `DEPLOYING`) reads via `run.terraform_plan["approval_workspace"]`; B's `_verify_approved_plan_recoverable` then fails ("workspace no longer exists"). The P2 candidate fixed only the setup re-read path. A deterministic two-owner regression design is specified in the research doc §9.
3. Multi-resource gap confirmed: `DEFAULT_ALLOWED_RESOURCES` admits Deployment+Service+ConfigMap; rollback compensates only Deployment pod templates (official docs: revision created iff `.spec.template` changes; rollback restores only the Pod-template part); created resources are never removed (`delete` forbidden by sandbox policy); an unpinned undo targets the Deployment's own last revision, not this run.

**Official documentation facts recorded.** `--to-revision` "Default to 0 (last revision)"; revision semantics; `revisionHistoryLimit` (default 10, 0 disables rollback); `pod-template-hash` and `deployment.kubernetes.io/revision`; `resourceVersion`/`409 Conflict`; single-resource verbs (no multi-object transaction); dry-run side-effect guarantee; SSA managed fields/conflicts and `force` ownership transfer (force-overwrite prohibited as automatic recovery). Repository pins: kubectl v1.31.4 (`e2e/pinned-kubectl.txt`), Redis `redis:7.2-alpine@sha256:29e8589c…` in `ci.yml`.

**Design decisions (research doc).** Versioned bounded per-attempt evidence inside `run.execution` (attempt_id, schema_version, operation, manifest_sha256, target resources, identity digest, handed_off_at, HANDOFF_PENDING→RESULT_RECORDED, result, monotonic `may_have_mutated`) persisted by the same fenced commit; fail closed when persistence fails (no untracked handoff); run-scalar monotonic `kubernetes_may_have_mutated`; **no** separate Redis journal (the P1-2 journal's fence-race rationale does not transfer — the apply writer is the fence owner). Rollback gated on durable handoff evidence; legacy in-flight records ⇒ `LEGACY_UNKNOWN` treated as may-have-mutated (never `NOT_ATTEMPTED`); rollback metadata (`NOT_REQUIRED`/`PARTIAL`/`NOT_COMPENSATED`, `coverage: pod-template-only`) with no new state transitions; `ROLLED_BACK` only for complete passing compensation. Stale-worker discard gated on fencing-confirmed terminality. Pinned-revision capture, conditional restore, SSA restoration and Service/ConfigMap/creation compensation deferred to a separately scoped compensation subsystem. Explicit recorded limitation: `kubectl rollout undo` (pinned or not) has no conditional semantics; read-then-undo is not atomic.

**Artifact.** `docs/PHASE-8.8A-KUBERNETES-ROLLBACK-SAFETY-RESEARCH.md` created (15 required sections; every claim labeled Verified-in-local-source / Verified-by-test-evidence / Official-external-documentation / Engineering-recommendation / Unverified-hypothesis). `PROJECT_STATE.md` updated so the next task is the reviewed rollback-safety implementation. `ARCHITECTURE.md` corrected only where its implemented-behavior claim was falsified by this research (approval-workspace disposal and the rollback defect statement).

**Validation.** None claimed for the design. No tests were implemented or run for the new matrix (§12 of the research doc). CI plan uses Python 3.11, the existing redis-integration/kind jobs, and the pinned digests; nothing may be claimed passed before a hosted run at the exact implementation SHA.

**Disposition.** Research complete; implementation not started. No commit, push, PR, merge, deployment, or main modification was made.

## 2026-11-14 — Phase 8.8A rollback authorization and recovery-safety amendment (design only)

**Objective.** Amend, rather than re-run or implement, the rollback-safety research after
an independent devil's-advocate review. No application code, tests, CI, infrastructure,
migrations, commits, pushes, PRs, merges, deployments, or main-branch changes were made.

**Git evidence.** Initial state: `fix/p2-recovery-cleanup` at
`72189146ceb3206a9ecd7a8734d26cac7ab16275`, with the pre-existing four modified
application/test/findings paths and six untracked documentation paths. `origin` remained
`https://github.com/gm-prog/Autonomous-Devops-Engineer.git`; `e1d0040` and `b75cc30`
remain ancestors. The original checkout was not touched. Final state is the same HEAD and
branch; only the three required documentation handoff files were edited in this pass.

**Verified local source.** The kubectl sandbox exposes only server-side dry run, apply,
rollout status, and unqualified rollout undo; the fixed undo argv carries no UID,
resourceVersion, template identity, read operation, conditional patch, or `--to-revision`.
The default manifest allowlist is Deployment, Service, ConfigMap. The manifest resource
list and Kubernetes attempt history currently have no limit. The worker's stale local
`LEASE_LOST` path can delete the shared approval workspace after its fenced commit is
rejected; its private execution workspace is distinct and safe to remove.

**Verified v1.31.4 behavior and official sources.** The checked-in pin is `kubectl
v1.31.4`, Linux amd64 SHA-256
`298e19e9c6c17199011404278f0ff8168a7eca4217edad9097af577023a5620f`. The matching
Kubernetes source tag/commit is `v1.31.4` / `a78aa47129b8539636eb86a9d00e31b2720fe06b`.
Its apply command uses `ContinueOnError`, processes retained objects sequentially, and
returns aggregated errors: a failed invocation can follow partial mutations. Official
Deployment/API/SSA documentation confirms template-only deployment rollback, pruneable
history, and object-scoped optimistic concurrency/conditional patch semantics.

**Amended decisions.** Attempt evidence and rollback authorization are separate. In P2.1,
attempt evidence is persisted under the worker fence before sandbox handoff, is monotonic,
has a maximum 32-resource non-evictable per-resource summary and 16 detailed attempts,
and fails closed before any new mutation when capacity/persistence is unavailable. It can
never independently authorize undo: missing current-resource authorization produces
`BLOCKED` / `OPERATOR_REQUIRED`, preserves evidence, and never claims `ROLLED_BACK`.
P2.1 also adopts `COMPLETE`, `PARTIAL`, `BLOCKED`, `FAILED`, and `NOT_REQUIRED` outcomes;
only verified `COMPLETE` maps to `ROLLED_BACK`. The shared plan may be removed only after
the deleting active worker's terminal fenced commit succeeds, before it releases the
lease; rejected stale commits authorize no shared deletion. The deterministic two-owner
real-Redis regression is immediate P2.1 scope. Conditional capture/restoration is P2.2;
Linux/Redis/Celery/Kind/operator-concurrency/hosted-CI acceptance is P2.3.

**Documentation and validation.** Appended the clearly labeled amendment to
`PHASE-8.8A-KUBERNETES-ROLLBACK-SAFETY-RESEARCH.md`; updated this log and
`PROJECT_STATE.md`. `ARCHITECTURE.md` was not changed because no implemented architecture
fact changed. `git diff --check` was run after the edits. No implementation test was run,
as this was research-only. Unresolved server-specific pruning/no-prior-revision behavior,
resourceVersion churn, and API-consumer audit are documented as `BLOCKED` conditions,
not assumptions that permit automatic rollback.


<!-- P2.1-MANUAL-AUDIT-WORKLOG-2026-11-14 -->
## 2026-11-14 — P2.1 manual final-audit kickoff

**Objective.** Continue the P2.1 final engineering audit manually after the OpenCode and Codex usage quotas were exhausted. This is an audit and validation task, not a reimplementation. P2.2 conditional Kubernetes compensation and P2.3 integration acceptance remain out of scope.

**Local checkout evidence (operator-provided PowerShell output).**

- Recovery checkout: `C:\Users\deysa\Autonomous-Devops-Engineer-p2-recovery`.
- Branch: `fix/p2-recovery-cleanup`.
- HEAD: `72189146ceb3206a9ecd7a8734d26cac7ab16275`.
- Shell: Windows PowerShell 5.1.
- Modified tracked files: `deployment_engine.py`, `kubectl_runner.py`, `kubernetes_manifest_policy.py`, `test_deployment_engine.py`, `test_execution_lease.py`, `test_release_identity_injection.py`, and `docs/PHASE-8.8A-CORRECTION-1-FINDINGS-MATRIX.md`.
- Untracked files: `AGENTS.md`, `CLAUDE.md`, `kubernetes_operation_evidence.py`, `docs/ARCHITECTURE.md`, `docs/PHASE-8.8A-KUBERNETES-ROLLBACK-SAFETY-RESEARCH.md`, `docs/PROJECT_STATE.md`, and `docs/WORK_LOG.md`.
- Operator-reported `git diff --stat`: 2,425 insertions, 81 deletions, 7 tracked files.
- No staged paths were reported.
- `git diff --check` and `git diff --cached --check` produced no errors.
- No destructive Git command or commit/push/merge/deploy action was performed.

**Evidence classification.** The checkout identity, working-tree inventory, diff summary, and whitespace-check result above are from terminal output supplied by the operator. They were not executed directly by this reviewer. The contents of `AGENTS.md`, `CLAUDE.md`, `PROJECT_STATE.md`, `ARCHITECTURE.md`, and `WORK_LOG.md` were supplied for inspection. A GitHub lookup independently confirmed the base commit exists and a remote branch search for `fix/p2-recovery-cleanup` returned no match; the uncommitted P2.1 working diff is not available from that remote lookup.

**Implementation/test status.** P2.1 implementation is present in the local working tree according to the file inventory and prior agent report. No source-level P2.1 verdict is made in this kickoff entry. Prior OpenCode test counts remain agent-reported until independently reproduced or checked against exact captured logs. In particular, dispatch-contract validation remains outstanding, and Redis broker tests must use a disposable isolated Redis instance; do not touch the possibly shared service on `127.0.0.1:6379`.

**Audit order.**

1. Inspect `kubernetes_operation_evidence.py` and validate schema parsing, fail-closed malformed-state handling, attempt IDs, result association, monotonicity, and resource/attempt capacity behavior.
2. Inspect `kubernetes_manifest_policy.py` and prove the 32-resource limit is applied to canonical unique resources and cannot be raised by callers.
3. Inspect `kubectl_runner.py` to verify `before_handoff` executes exactly once for apply, after all preflights and immediately before sandbox handoff; verify no rollback undo is invoked in P2.1.
4. Inspect `deployment_engine.py` end-to-end: evidence persistence before handoff, result commit behavior, legacy `DEPLOYING` handling, rollback outcome aggregation, Terraform uncertainty, fenced cleanup authorization, and every retry path that may need the shared approval workspace.
5. Audit the rollback evidence consumer for compatibility with old records and the new `rollback.outcome` field.
6. Inspect all added/modified tests, including the reported test scenarios 01–35; use actual test names from source.
7. Run tests in safe order; isolate broker-backed dispatch tests on a disposable Redis instance and verify DB0 broker / DB1 application-store routing before execution.
8. Record exact commands, interpreter/runtime, exit codes, pass/skip/fail counts, and exact failing node IDs. Distinguish code defects, Windows limitations, unavailable infrastructure, and unrelated baseline issues.
9. Review the complete diff and update project state, work log, and research disposition with verified findings and residual limitations.
10. Produce a strict GO/NO-GO review. Do not commit, push, merge, deploy, or alter `main`.

**Priority risks to resolve.** Rollback `status` versus `outcome` consumer compatibility; legacy in-flight uncertainty; unambiguous attempt/result ID association; canonical resource cap behavior; stale-worker deletion of the shared approved workspace; Terraform timeout/cancellation ambiguity; `PARTIAL` versus `COMPLETE` aggregation; result-commit failure after durable handoff; Windows path assertion strength; and mutation-test child-interpreter validity.

**Disposition.** Audit kickoff only. No application changes, test execution, or merge-readiness approval is claimed by this entry. Preserve all local work and keep the original checkout untouched. See [P2.1-MANUAL-AUDIT-CHECKPOINT-2026-11-14.md](P2.1-MANUAL-AUDIT-CHECKPOINT-2026-11-14.md) for the detailed resume packet.


## 2026-11-15 — P2.1 PR #16 pushed; CI and review handoff

**Objective.** Preserve the exact state and next actions for a fresh agent reviewing P2.1 PR #16.

**Verified remote GitHub state.** PR #16 is open, not merged, non-draft, and reported mergeable. Head `fix/p2.1-kubernetes-attempt-correlation` at `1ccf210451920f2015b954bdec9fb4527606813a`; base `arena/p2.1-result-contract-fix-20261114` at `334c87a2341da1393922a405e780c5e371e61ed8`. PR contains six changed files, 118 additions, 39 deletions, and nine commits. No PR reviews are recorded. See https://github.com/gm-prog/Autonomous-Devops-Engineer/pull/16.

**Implementation delivered.** Lease-fenced pre-apply handoff evidence; exact per-invocation attempt-ID/result correlation; stale-worker result-commit rejection preserves uncertainty and shared approval workspace; no automatic Kubernetes compensation authorization; explicit runner `exit_code`/`timed_out`/`cancelled` result fields; updated strict test fakes; byte-identical UTF-8 artifact/sidecar hashing and writing.

**Changed paths.**
- `devops-ai-platform/deployment_service/application/services/deployment_engine.py`
- `devops-ai-platform/deployment_service/application/services/kubectl_runner.py`
- `devops-ai-platform/deployment_service/application/services/kubernetes_operation_evidence.py`
- `devops-ai-platform/deployment_service/tests/test_deployment_engine.py`
- `devops-ai-platform/deployment_service/tests/test_execution_lease.py`
- `devops-ai-platform/e2e/evidence_provenance.py`

**Local validation (operator-provided terminal output).** Ubuntu WSL2, Python 3.11.18, hash-pinned test dependencies, Redis integration container on port 6399. Targeted three-file selection: 96 passed in 7.73s. Full `deployment_service/tests`: 687 passed, 1 skipped, 34 subtests passed in 27.64s. `git diff --check` passed. The earlier Windows full-suite attempt had 11 platform-related failures involving symlinks, FIFO support, POSIX ownership/mode bits, and `signal.SIGKILL`; do not make production changes merely to accommodate those Windows limitations.

**Hosted CI at exact PR head SHA.** Workflow run [43691344471](https://github.com/gm-prog/Autonomous-Devops-Engineer/actions/runs/43691344471) had 12 check-runs at inspection: 9 success, 1 failure (`Phase 8.5-A terraform execution trust boundary`, job 132742465191), 1 in progress (Android unit tests + debug build, job 132742465278), and CodeRabbit skipped because reviews are disabled for the base branch. The legacy commit status endpoint was pending with zero statuses. No PR reviews/approvals exist. Do not call CI green.

**Disposition: NO-GO for merge.** Independently inspect the Terraform failure, wait for the Android job, review the complete six-file diff, verify the actual required-check policy for the base branch, and obtain review approval. Only then reassess merge readiness. No merge was performed.

**Next-agent start.** Follow `AGENTS.md` read order. First inspect run 43691344471 / job 132742465191 logs and annotations; then recheck job 132742465278; then complete the six-file security/correctness review. Preserve the safety invariant: operation evidence records possible mutation but never authorizes automatic rollback. P2.2 and P2.3 remain separate follow-on scopes.
