# DevOps.AI Operator Platform (DDD)

The bounded-context microservices platform for the DevOps.AI autonomous
DevOps engine.

## What runs today

As of this development round, **every service in this directory is importable
and has a bootable entrypoint** (verified by the `tests/` smoke suite, run in
CI):

| Service | Package | Entrypoint | Exposes |
|---|---|---|---|
| BFF Gateway | `api_gateway` | `api_gateway.main:app` :8000 | `POST /v1/gateway/dispatch/{service}`, `GET /v1/gateway/metrics`, control plane `POST /v1/deployments/dry-run`, `/v1/deployments/{id}/approve`, `/execute`, `/v1/incidents/{id}/remediation`, `GET /v1/incidents/{id}/proposal`, `POST /v1/incidents/{id}/proposal/approve`, `POST /v1/incidents/{id}/proposal/execute` (HS256 JWT, operator roles where noted), `/health` |
| Repo context | `repo_service` | `repo_service.main:app` :8010 | `POST /repositories`, `/health` |
| Agent swarm | `agent_service` | `agent_service.main:app` :8020 | `GET /agent/streams/{task_id}` (SSE), `/health` |
| Deployment | `deployment_service` | Celery worker | task `tasks.execute_iac_deployment` (Redis broker) |
| Monitoring | `monitoring_service` | `monitoring_service.main:app` :8040 | `WS /ws/telemetry/socket/{client_id}`, `POST /api/internal` (observation → threshold event, dispatch target), `/health` |
| Incident | `incident_service` | `incident_service.main:app` :8050 | `GET /incidents`, `POST /incidents/{id}/remediation` (provenance-bound), `POST/GET /incidents/{id}/proposal` (Phase 6.1, proposal-only), `POST /incidents/{id}/proposal/approve` + `/execute` (Phase 6.2, approval → draft PR), `POST /alerts/webhooks/sentry` (HMAC, fail-closed), `/health` |
| Reporting | `reporting_service` | (library) | weekly audit-report queries + "PDF" engine |
| Shared kernel | `shared_kernel` | (library) | domain events, value objects, event publisher, metrics |

## Run the full stack

```bash
# 1. infrastructure + all services (Docker required)
docker-compose up -d --build

# 2. mint a gateway token and exercise the BFF
export TOKEN=$(python -m api_gateway.core.auth devops-operator DevOpsLead)
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/v1/gateway/metrics
```

## Run without Docker (single service)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# from this directory, any service:
uvicorn api_gateway.main:app --port 8000
uvicorn repo_service.main:app --port 8010
uvicorn agent_service.main:app --port 8020
uvicorn monitoring_service.main:app --port 8040
uvicorn incident_service.main:app --port 8050

# deployment service is a Celery worker:
celery -A deployment_service.infrastructure.celery.tasks.celery_app worker --loglevel=info
```

## Security model

* **Gateway auth** — real HS256 JWT verified with `JWT_SECRET`
  (`api_gateway/core/auth.py`). The old "any token ≥ 10 chars is a
  Developer" mock is gone. Mint dev tokens with
  `python -m api_gateway.core.auth <subject> [roles...]`. If `JWT_SECRET` is
  unset, a committed development fallback is used **and a warning is logged**
  — set a real secret before exposing the gateway.
* **Control plane** — deployments and remediation are driven through named
  gateway routes (`/v1/deployments/*`, `/v1/incidents/{id}/remediation`),
  not by proxying guessed `/api/internal/*` paths (which 404 at the
  gateway). Every route requires a valid JWT; `approve`, `execute` and
  `remediation` additionally require an operator role
  (`operator`, `DevOpsLead`, `ClusterAdmin`) else **403 before any
  downstream call**. The gateway stamps `requested_by` / `approved_by`
  from the JWT `sub` — caller-supplied identity strings are overwritten.
  The product is intentionally **single-operator**: any operator may act
  on any run/incident id (no per-user tenancy is claimed or invented);
  ids must exist downstream (404/409 relayed), deployments are guarded by
  the state machine + hash binding, and remediation by evidence binding.
* **Sentry webhooks** — `incident-service` verifies an HMAC-SHA256
  signature of the raw body (`X-Sentry-Signature`) with a constant-time
  compare. **Fail closed:** if `SENTRY_WEBHOOK_SECRET` is unset the
  endpoint rejects every request with **HTTP 503** until configured —
  there is no permissive mode, and `verify_sentry_signature` itself
  returns False without a secret.
* **Deployment provenance** — see "Deployment provenance & source
  verification" below: remediation authorization requires a DEPLOYED run
  whose platform provenance record verifies (hash + identity + source
  verification), not a plausible repository name + SHA.
* **GitHub PR client** — refuses to fabricate PR URLs: a missing
  `GITHUB_OAUTH_TOKEN` now raises instead of "succeeding".

## Remediation runtime & deployment evidence contract

The incident bounded context ships the full remediation path
(`incident_service` package, package-mode entrypoint
`uvicorn incident_service.main:app`):

```
POST /incidents/{id}/remediation          (binding-gated, see below)
  -> isolated workspace @ pinned 40-hex source SHA
  -> bounded patch (`git apply --check`) -> bounded validation profiles
  -> deterministic commit (parent == pinned SHA)
  -> git push automation/remediation/* (http.extraHeader credentials)
  -> remote SHA verification (ls-remote) -> GitHub REST branch + DRAFT PR
  -> real html_url; every boundary fails closed
```

**Target binding:** the endpoint first proves the requested
`repository_slug` + `source_sha` appear in the incident's own
`deployment_run` evidence (403 + orchestrator never invoked otherwise).

**Deployment evidence contract** (`GET /api/internal/deployments/{run_id}`
on `deployment-service:8030`, served by `deployment_service.main:app`):

| Field | Meaning |
|---|---|
| `id` | deployment run id |
| `repository_id`, `repository_name` | repository identity (`owner/repo`) |
| `source_revision.head_sha` | full 40-hex revision deployed |
| `source_verification` | independent source check attestation (`method`, `verified_at`, remote commit id); never contains credentials |
| `provenance` | canonical-JSON-hashed provenance record (see below), re-derived on every save |
| `state`, `created_at`, `updated_at`, `artifact_hash`, `plan_hash`, `approval`, `health_check`, `rollback`, `error` | bounded run metadata |

Records are produced by `POST /api/internal/deployments/dry-run` (then
approve/execute) and persisted in the run store; unknown run ids return
**404** - responses are never synthesized. `incident-service` reads this
endpoint through `DeploymentEvidenceCollector` (`DEPLOYMENT_SERVICE_URL`)
when attaching evidence.

## Deployment provenance & source verification (Stage 5)

The trust chain from request to remediation is:

```
caller picks repo + exact SHA
  → HTTP boundary: canonical owner/repo + full 40-hex only
  → server-side source verification: GitHub commits API confirms that exact
    SHA exists in that exact repository (Bearer token from env, header-only;
    404 → 422, provider trouble → 503 — both fail closed, no run persisted)
  → artifact identity: sha256 of the submitted IaC; plan identity binds
    artifact + repo + source revision + tool outputs
  → approval (hash-bound) → execute (re-checks hashes) → state=DEPLOYED
  → evidence collector copies the run, including its provenance record
  → remediation binding: ONE DEPLOYED evidence record whose provenance
    verifies AND whose (repo, SHA) equals the requested target
  → orchestrator constructed only after that gate passes
```

**Provenance record** (`shared_kernel/domain/provenance.py`, schema
`devops.deployment-provenance/1`): `repository_name`, `source_sha`,
`artifact_hash`, `plan_hash`, `deployment_run_id`, `state`,
`verification_method`, `artifact_source_derivation`, plus
`provenance_hash` = SHA-256 over the canonical JSON (sorted keys, compact
separators) of all other fields. It is **re-derived from the run's own
persisted fields on every save** — never read back from requests or
storage, so no HTTP field can rewrite it. Remediation binding recomputes
the hash and cross-checks every identity field against the evidence
record; `verification_method: "unverified"`, tampering, grafting from
another record, or a state mismatch all fail closed.

**What the platform claims — and what it deliberately does not:**

* *Source-verified:* the exact revision's existence in the canonical
  repository is confirmed server-side before any run exists.
* *Artifact-identity-verified:* the submitted IaC bundle is content-hashed
  and that hash is bound through plan → approval → execution.
* *Artifact-to-source derivation:* **not established**
  (`artifact_source_derivation: "not-established"`). The platform does not
  deterministically generate artifacts from the verified source tree, and
  the builder/verifier refuse to record or accept a stronger claim.
  Nothing here should be described as "cryptographic source-to-artifact
  provenance".
* The provenance hash is **unkeyed integrity, not a signature**: it
  detects tampering and cross-record grafting, while authenticity rests
  on the network/gateway boundary below.

## Phase 6.1 — Incident → evidence → RCA → remediation proposal (proposal-only)

```text
monitoring breach → ThreatThresholdExceededEvent (devops:events)
  → idempotent incident ingestion (ids derived from event_id, uuid5)
  → deployment evidence (existing collector command; DEPLOYED + provenance)
  → evidence pack (deterministic timeline, existing builder)
  → RcaAnalyzerPort → schema-validated RootCauseAnalysis (fail-closed)
  → trusted target resolution (Stage-5 gates, one-record pair)
  → HotfixProposal + deterministic rules (single-file, path policy, risk)
  → canonical proposal_hash → persisted for human review
```

* **Producer wiring (live vertical slice):** the monitoring runtime now
  composes the real chain — `monitoring_service.main` wires
  `application/dependencies.build_threshold_monitor()` (env config
  `MONITORING_DANGER_LIMIT`, default 90.0) → `RedisStreamPublisher`
  (env `EVENT_BUS_REDIS_URL` / `EVENT_BUS_STREAM`, default
  `devops:events`) → existing `ThresholdValidator`. Input arrives at
  `POST /api/internal` (the target of the gateway's generic
  `dispatch/monitoring` proxy; envelope `{"payload": <observation>,
  "forwarded_by": <jwt sub>}`); a breach publishes
  `ThreatThresholdExceededEvent` using the exact stream-field envelope
  `RedisIncidentEventConsumer` deserializes
  (`event_id`/`event_type`/`aggregate_id`/`timestamp`/`payload`). The
  incident-event-worker consumes it with the existing idempotent handler.
  Compose provisions monitoring with the event bus env + redis dependency
  (still no host ports). Fakes sit only at adapter boundaries (Redis
  client, RCA port) — the composition path itself is the production one.
* **Idempotency (§4):** incident id = `uuid5(event_id)`; threshold evidence
  id likewise. Redelivering the same event returns the existing incident and
  never duplicates evidence; proposal regeneration upserts by deterministic
  `proposal-{incident_id}` (one proposal, one RCA result, stable hash).
* **RCA (§10/§11):** application-level `RcaAnalyzerPort.analyze` (agent-service
  HTTP adapter in production, deterministic fakes in tests). The aggregate
  never calls an LLM. Results are schema-constrained fail-closed: bounded
  types/lengths, confidence within [0, 1], and **every `evidence_ref` must
  exist on this incident** — anything else raises `InvalidRcaResult` (HTTP
  422) and nothing is persisted. Legacy `supporting_evidence_ids` is
  accepted as an alias.
* **Trusted target (§6/§7):** `resolve_authoritative_deployment_target`
  reuses the Stage-5 binding gates (state `DEPLOYED`, canonical `owner/repo`
  + full 40-hex SHA coexisting in ONE evidence record, valid platform
  provenance) and selects the most recent qualifying record. No candidate →
  proposal `status=BLOCKED`,
  `blocked_reason=MISSING_DEPLOYED_TARGET_EVIDENCE`, empty repository/SHA —
  never a fabricated repo, SHA, run or artifact.
* **Proposal content (§12–§15):** id, incident_id, root_cause, confidence,
  target_repository, source_sha, `files[{path,patch}]` (single file),
  validation_plan, risk_class, evidence_refs, proposal_hash, status,
  blocked_reason. AI output may propose `target_file`, `patch`,
  `validation_plan`, `risk_class` only — `repository`, `source_sha` and
  identity fields in provider output are rejected outright. Validation
  reuses `HotfixProposal.apply_verification_pass()` (single-file unified
  diff) and `HotfixValidationService` (size, security-path,
  protected-path, confidence rules).
* **Risk + hash (§17/§18):** deterministic classifier
  (`LOW|MEDIUM|HIGH|BLOCKED`) derived from confidence, uncertainty,
  contributing factors, incident severity and the AI-suggested class (which
  can only raise, never lower, the result). Hash = SHA-256 over fixed-field
  canonical JSON (sorted keys, compact separators) of incident_id,
  root_cause, evidence_refs, repository, source_sha, file paths, patch,
  validation plan and risk — timestamps and dict order never matter.
* **Persistence (§19/§20):** through the existing incident repository (no
  separate database). Success upserts one verified proposal, moves the
  incident to `RemediationProposed`, and every field survives reload;
  failures persist a non-executable `BLOCKED` proposal (`is_verified=false`)
  without promoting the incident.
* **API:** `POST /incidents/{id}/proposal` (200 for PROPOSED **and**
  BLOCKED outcomes — the pipeline ran; blocked bodies carry a
  machine-readable `blocked_reason`; 404 unknown incident, 422 malformed
  RCA, 503 provider/persistence outage) and read-only
  `GET /incidents/{id}/proposal`. At the gateway:
  `GET /v1/incidents/{id}/proposal` requires a valid JWT **and** an
  operator role; the internal URL prefix grants nothing.
* **Observability (§26):** single-line JSON logs with correlation ids —
  `incident.created`, `evidence.attached`, `rca.started`, `rca.completed`,
  `proposal.generated`, `proposal.validated`, `proposal.blocked` (plus
  `rca.failed`, `incident.duplicate_ignored`). No tokens, headers or full
  AI outputs are ever logged.

**Guarantee — proposal only.** Phase 6.1 never clones, modifies, commits,
pushes, creates branches/PRs, deploys, approves or executes remediation.
`ApplyAutomatedFixCommandHandler`, the remediation orchestrator and the
GitHub client are covered by no-side-effect spy tests that still require a
fully produced + persisted proposal (§22). `risk_class` is metadata and can
never trigger execution.

### Honest limitations (Phase 6.1)

* RCA confidence is **probabilistic**, not a correctness guarantee; the
  derivation of the conclusion from the cited evidence is not formally
  established. `evidence_refs` prove the references exist on this incident,
  not that the causal claim is true.
* Service-to-service authentication (incident → agent-service) relies on
  the private compose network; a second token system and TLS between
  services are future work (documented in the trust-boundary section).
* Proposal validation runs the deterministic rule service in-process — the
  same non-isolation limit as the remediation validation runner (below).
  `git apply --check` is **not** run in Phase 6.1: a proposal-only pipeline
  never materializes a source snapshot, so there is no tree to check
  against (noted honestly instead of skipped silently).
* Stream production runs through the real composed publisher; CI fakes
  only the Redis client (adapter boundary) and does not run a live Redis.
  The gateway→`/api/internal` hop is covered by the dispatch proxy tests;
  the monitoring receiver itself is exercised directly as an in-network
  caller.

## Phase 6.2 — Controlled remediation execution (proposal → approval → validated patch → draft PR)

```text
POST /incidents/{id}/proposal        (Phase 6.1: persisted proposal)
  → operator approval at the gateway (JWT sub stamped, never request text)
  → deterministic approval policy (state/hash/TTL/risk/target — re-verified)
  → execution pre-flight: canonical hash recompute, patch policy re-check,
    authoritative deployment target re-resolution (same DEPLOYED record
    + repo + SHA as the proposal — never retargeted)
  → EXECUTING persisted (uuid5 execution id, attempt counter)
  → existing orchestration: isolated SHA-pinned workspace → bounded patch
    (git apply --check) → fixed validation profile → deterministic commit
    (parent == pinned SHA) → push automation/remediation/* → remote SHA
    verified → GitHub REST branch + DRAFT PR
  → PR_CREATED persisted + machine-readable execution evidence
```

**The AI proposes; deterministic code authorizes; deterministic code
executes; independent checks verify.** The request body never carries
`repository`, `source_sha`, branch, workspace or commands — those are
always derived from the persisted proposal and re-validated against the
authoritative deployment evidence immediately before side effects.

* **Approval policy (`POST /incidents/{id}/proposal/approve`, operator
  only at `/v1/...` at the gateway).** Requires: incident + proposal
  exist, status `PROPOSED` (idempotent re-approval of the same approved
  hash is accepted), reproducible canonical hash == stored hash ==
  caller claim, risk class inside the deliberately small
  `LOW`/`MEDIUM` set, generation → approval within
  `REMEDIATION_PROPOSAL_TTL_SECONDS` (default 86400), and the
  authoritative deployment target still matching the proposal binding.
  AI confidence is never an authorization signal. `approved_by` is the
  verified JWT subject, never a request string.
* **Lifecycle:** `PROPOSED → APPROVED → EXECUTING → PR_CREATED`, failure
  → `EXECUTION_FAILED` (retryable). `BLOCKED` is never approvable.
  Approval fields (`approved_by/approved_at/approval_hash`) and
  execution fields (`execution_id/executed_at/commit_sha/branch_name/
  execution_attempts/last_failure_*`) persist on the existing aggregate —
  no new tables.
* **Idempotency & concurrency:** execution id =
  `uuid5(namespace, proposal_id:proposal_hash)` — same proposal, same
  identity, same PR. After `PR_CREATED` a repeat call reconciles the
  stored PR (no second push, no second PR). Concurrency is guarded by a
  process-local per-proposal lock (an optimization only) **plus** the
  durable storage-backed execution lease introduced in Phase 6.2.1
  below — the lease row, not the process lock, is the source of truth.
* **Failure semantics (§25 HTTP map):** 404 missing incident/proposal;
  422 integrity/patch-policy/validation-failed (and deterministic
  patch-stage failures); 409 not-approved/executing/stale; 403
  policy/target-revalidation; 502 GitHub/remote failure — persisted as
  `EXECUTION_FAILED` with stage + evidence, never a fake `PR_CREATED`.
  Validation failure stops before commit/push/PR every time.
* **Observability:** structured `remediation.*` JSON logs for
  `approval.accepted`, `target.revalidated`, `execution.started`,
  `workspace.created`, `patch.applied`, `validation.started`,
  `validation.completed`, `commit.created`, `pr.created`,
  `execution.completed`, `execution.failed`, `execution.reconciled`
  (ids, hashes, statuses, stage results — no secrets, no headers), plus
  persisted `remediation_execution` evidence records
  (`exec-{execution_id}-a{attempt}`) carrying the full stage list,
  validation step results, commit SHA and PR URL.
* **Command boundary:** execution runs only the fixed validation profile
  bound at composition (`REMEDIATION_VALIDATION_PROFILE`, default
  `incident_service`); `validation_plan` text from the proposal never
  becomes a command. Patch/branch/commit policy from the existing
  orchestration stack is re-applied on every attempt.

### Honest limitations (Phase 6.2)

* **Process-local locking superseded by Phase 6.2.1.** The 6.2
  process-local lock alone could not hold the single-execution
  invariant across replicas, and a crash mid-`EXECUTING` stranded the
  state — both addressed by the durable execution lease and
  crash-recovery reconciliation documented in Phase 6.2.1 below (with
  that phase's remaining honest limitations).
* **Workspace + subprocess validation is not a hardened sandbox** — no
  container/VM isolation, seccomp or user namespace separation. Bounded
  timeouts, resource limits, fixed argv and sanitized env are enforced,
  but a determined local exploit surface remains.
* **Non-fast-forward retry:** a failed attempt after a successful push
  retries with a plain push of the same deterministic branch; if the
  remote branch advanced unexpectedly the retry fails closed (no lease
  force).
* **GitHub "draft" and base-branch policy** rely on the configured
  `GITHUB_ALLOWED_BASE_BRANCHES` and token permissions; merging,
  approving, deploying, canary or rollback remain explicitly out of
  scope.

## Phase 6.2.1 — Durable execution coordination & remote reconciliation

One logical proposal execution converges to **one logical remediation
result** under duplicate, interrupted or ambiguous requests.

```text
POST /incidents/{id}/proposal/execute   body: {proposal_id, proposal_hash} ONLY
  → integrity (canonical hash == approval == claim) + freshness + target gates
  → durable claim: atomic INSERT/UPDATE on devops_execution_claims
       at most one live lease for (incident_id, proposal_id, proposal_hash)
  → recovery inspects reality BEFORE any side effect:
       durable cursor + local HEAD/parent + `git ls-remote` branch SHA
       + GitHub PR discovery (`find_existing_pull_requests`)
  → RESUME (remote == persisted commit) or FULL restart (no remote evidence)
  → existing orchestration with durable stage transitions
  → owner-gated finish: PR_CREATED/COMPLETED or EXECUTION_FAILED + evidence
```

### Execution lease (durable, storage-backed)

* **Table `devops_execution_claims`** (same database as incidents):
  `incident_id, proposal_id, proposal_hash, execution_id, attempt,
  lease_owner, lease_acquired_at, lease_expires_at, current_stage, state`
  (`FREE|LEASED`) plus `heartbeat_at, completed_at, failure_*,
  commit_sha, branch_name, pull_request_url`. The claim row is
  authoritative; proposal JSON carries mirrored fields projected on read.
* **Atomic claim invariant:** at most one live lease per
  `(incident_id, proposal_id, proposal_hash)` — enforced by insert-or-CAS
  update inside one short transaction, verified between **independent
  service instances** (two adapters over one SQLite file), not merely
  between threads. A fresh lease can never be stolen; an expired lease is
  reclaimable only via the same atomic CAS (previous owner included).
* **TTL:** `REMEDIATION_EXECUTION_LEASE_SECONDS` (default `600.0`,
  must be a positive finite number — invalid values fail fast at
  construction). Every progress write renews expiry; expiry is computed
  with tz-aware UTC instants.
* **Owner identity is process-derived** (`new_lease_owner()` embeds pid
  + monotonic time); the `execute()` interface accepts **no** owner,
  repository, branch or target parameters — callers cannot choose lease
  identity or execution targets.
* **Attempt semantics:** `attempt` increments only on a successful
  claim (a real ownership acquisition). Duplicate polls or
  `PR_CREATED`-state reconciliations never increment it.
* **Reclamation policy:** active lease → reject
  (`ExecutionLeaseUnavailable`/409); expired + no remote evidence →
  safe restart from a verified stage; expired + remote evidence →
  reconcile first (RESUME); inconsistent → fail closed with a durable
  reconciliation conflict — never retarget or force-push.

### State machine (documented, enforced)

```text
PROPOSED → APPROVED → EXECUTING → PR_CREATED
                        ⇅
               EXECUTION_FAILED   (retryable — fresh claim, revalidated)
EXECUTION_FAILED → PR_CREATED ONLY via remote provenance (discovery of the
                    already-created PR), never by direct status assignment.
```

Durable stage vocabulary (bounded, persisted one short transaction at a
time, never while an external op is in flight):
`CLAIMED → WORKSPACE_CREATED → PATCH_APPLIED → VALIDATION_STARTED →
VALIDATION_PASSED → COMMIT_CREATED → REMOTE_PUBLISHED → REMOTE_VERIFIED →
PR_DISCOVERY → PR_CREATED → COMPLETED | FAILED`.
A stage never claims a mutation before it is verified, and `PR_CREATED`
is written only after a validated PR response with a known PR identity.
If the lease is lost mid-run (owner CAS fails at any stage write) the
orchestrator aborts via `RemediationStageGuardError` and the failure is
persisted only if ownership still holds — otherwise the new owner's
state is never clobbered.

### Recovery semantics (crash-safe)

* Crash after `EXECUTING`, after commit, after push, after branch
  before PR, or on a PR-response timeout: the next claim sees the
  durable cursor and inspects reality —
  * remote branch absent + durable commit not published → full
    deterministic restart (same branch, same parent, new attempt);
  * remote branch == persisted commit → **resume**: skip workspace,
    re-inspect, reconcile PR (idempotent);
  * remote branch ≠ persisted commit → `RemoteBranchConflict` (409),
    durable `RECONCILIATION_CONFLICT` evidence, no force-push;
  * remote unreachable/ambiguous → `RemoteReconciliationFailed` (502)
    with a durable conflict record — never a guessed outcome.
* Every recovery re-runs the full gate stack first: canonical
  hash == approval == claim, patch policy, authoritative deployment
  target (no retarget), proposal TTL, and lease TTL. Stale/tampered/
  drifted state stops before any inspection or side effect.

### Remote reconciliation (mandatory before create)

* **Branch:** deterministic identity
  `automation/remediation/{incident}/{proposal}` derived only from
  persisted values. Pre-push: absent → normal push + SHA verify;
  equal → idempotent (no push); different → fail closed. GitHub ref
  creation mirrors the same rules (never update an existing ref).
* **PR:** `find_existing_pull_request(s)` on the same GitHub client runs
  before every `POST /pulls` — auth required, slug/base allowlist
  validated, bounded timeouts, distinct 401/403/404/429/5xx typed
  outcomes, no token in any message. **head/base/repository are the
  identity**; body metadata (`Incident:`, `Proposal:`, `Proposal hash:`,
  `Source SHA:`, `Remediation Commit:`) is corroborating evidence only —
  remote state is never authorization. Policy: 0 → create; 1 open
  matching → reuse; merged/closed → `ExistingPullRequestConflict` (409)
  no second PR; >1 matches or unexpected content → fail closed; title is
  never a search key.
* **HTTP map additions:** 409 adds `ExecutionLeaseUnavailable`,
  `RemoteBranchConflict`, `ExistingPullRequestConflict`; 502 adds
  `RemoteReconciliationFailed`. Active lease → 409 (no parallel
  execution); retry after success → the existing result; an
  unrecoverable conflict stays `EXECUTION_FAILED` until operator action.

### Delivery model & structured events

* **At-least-once execution with deterministic idempotency** — this
  system does **not** claim exactly-once or exact atomicity across
  database + Git + GitHub. Convergence comes from deterministic inputs,
  durable stage records and fail-closed reconciliation; recovery is
  deterministic (no randomness, memory, model output or request
  identity dependence).
* Events (redaction-safe): `remediation.lease.acquired|rejected|expired`,
  `recovery.started|reconciled`, `remote.branch.reconciled`,
  `pr.discovery|reconciled|created`, `execution.started|completed|
  failed|reconciled`. Observer failures never change semantics (only
  the stage-guard ownership signal aborts).

### Honest limitations (Phase 6.2.1)

* **Not distributed consensus.** The lease is a TTL-guarded CAS row —
  strong within one storage engine, not a k8s lease/Temporal/consensus
  protocol. Clock skew beyond the TTL window can extend an expired
  lease's apparent validity for observers until the next CAS; a
  partitioned worker whose writes fail simply aborts (fail closed).
* **Storage gap:** the claim/lease contract is exercised against the
  real SQLite persistence layer (two independent adapters, threaded CAS
  race included). The PostgreSQL DDL mirrors it one-to-one, but Postgres
  is not exercised in CI — run the §43 matrix against Postgres before
  claiming parity.
* **Remote evidence is shallow by design:** `ls-remote` + PR discovery
  see branch SHA and PR identity, not the full history of a hostile
  remote; anything unexpected fails closed to an operator.
* **PR body corroboration can be forged by a repo admin** — it only
  corroborates; authorization still comes from persisted approval state.

## Phase 6.2.1A — Lease liveness & remote identity integrity (corrective hardening)

Three review gaps closed on top of 6.2.1; no architecture change, the
at-least-once + deterministic-idempotency + reconciliation model is
preserved, and the pipeline still stops at **approved proposal →
controlled remediation → draft PR**.

### Active lease liveness (heartbeat)

* A worker-owned `_LeaseHeartbeat` thread starts immediately after the
  durable claim and stops (deterministically joined) on every exit path
  — success, typed failure, or unexpected error — before the owner-gated
  finish transaction, so renewal can never race the release.
* **Interval policy:** `REMEDIATION_EXECUTION_HEARTBEAT_SECONDS`
  (optional) or the derived default `lease / 3` — always positive,
  finite and strictly `< lease / 2`; anything else fails fast at
  construction (§4 policy, no hardcoded production value).
* **Renewal is durable and CAS-owned:** `renew_execution_lease`
  extends only `state == LEASED AND lease_owner == this owner` for the
  exact `(incident_id, proposal_id)` — it can never extend another
  worker's lease, resurrect a completed/reclaimed claim, or change the
  stage (no schema change: reuses `last_heartbeat_at` +
  `lease_expires_at`).
* **Lease-expiry safety rule (documented, tested):** an already-running
  git/HTTP operation is NOT cancelled. Instead —
  renewal success → continue; owner CAS miss or claim-store
  uncertainty → the worker is marked unauthorized **immediately**, and
  the stage guard refuses the *next* side-effecting boundary
  (`RemediationStageGuardError`) before workspace/patch/validation/
  commit/push/verify/discovery/create can begin. Failure persistence is
  still owner-gated; a worker that lost the lease cannot clobber the
  new owner's durable state. Database-uncertainty in persistence or
  finish paths is converted to typed fail-closed errors
  (`RemediationStageGuardError`/`ExecutionLeaseUnavailable`) —
  "store unavailable" never grants authority. Recovery proceeds through
  the existing expired-lease reclaim + reconciliation path.
* Thread hygiene: at most one daemon heartbeat per active attempt,
  bounded join in `stop()`, tests assert no thread accumulation across
  repeated success/failure runs.

### Exact PR identity (repository + branch + head SHA + base)

* `ExistingPullRequest` now exposes `head_sha` and `head_repository`
  (parsed from `head.sha` + `head.repo.full_name`; a missing/empty head
  SHA is a typed discovery failure — malformed payload).
* Reuse of an existing PR now requires ALL of:
  `head_repository == proposal.repository` AND
  `head ref == deterministic branch` AND
  `head_sha == the commit this execution produced` AND
  `base == allowed base` AND open AND not merged AND body
  proposal-hash corroboration. Wrong SHA, wrong/absent head repository,
  wrong base, merged/closed, multiple matches, or body-hash mismatch →
  `ExistingPullRequestConflict` (409): no second PR, no branch
  overwrite, no force-push, no retarget. The PR body remains untrusted
  corroboration only — never a source of commit identity, never parsed
  for instructions, title never searched.

### Multi-proposal claim projection

* The claim primary key is `(incident_id, proposal_id)`; the incident
  reload overlay now fetches **all** claim rows for the incident, indexes
  them by `proposal_id`, and projects each row only onto its own
  proposal. A proposal without a claim keeps its persisted JSON view;
  no proposal can inherit another's stage/attempt/lease/commit/branch/PR.
* **Authority model:** proposal JSON is authoritative for proposal
  contents, canonical hash, approval binding, target and RCA-derived
  data; the claim row is authoritative for ownership, lease state and
  timestamps, current stage, attempt, execution id, and the
  commit/branch/PR mirrors used for recovery. The overlay only projects
  coordination state — no dual authority.

### Honest limitations (Phase 6.2.1A)

* Renewal/stage CAS style is SQLAlchemy-portable, but **PostgreSQL
  concurrency is still not exercised in CI** (SQLite real-persistence
  tests only) — do not claim production-verified PG behavior.
* An operation already in flight cannot be cancelled after lease loss;
  only the next stage is blocked (bounded side effects + reconciliation,
  not distributed cancellation).
* Still no hardened sandbox (that is Phase 6.2.2), and no exactly-once
  transaction across DB + Git + GitHub.

## Phase 6.2.1B — Lease expiry enforcement & pre-side-effect authorization (corrective hardening)

Three review gaps closed on top of 6.2.1A; no architecture change, no
new infrastructure (no distributed mutex, no advisory locks, no long
transactions), the at-least-once + deterministic idempotency +
reconciliation model is preserved, and the pipeline still stops at
**approved proposal → controlled remediation → draft PR**.

### 1. Expiry-authoritative lease writes (Goal A)

`renew_execution_lease`, `persist_execution_progress` and
`finish_execution_lease` now require, inside the SQL statement itself
(both the read check and the final UPDATE CAS):

```
state = 'LEASED' AND lease_owner = :caller
AND lease_expires_at IS NOT NULL AND lease_expires_at > :now
```

Consequences: an expired worker can no longer renew, persist progress or
finish even though the row still names it as owner; after another worker
re-claims, the stale worker cannot release the new owner's lease or write
a terminal state (owner CAS and expiry CAS compose in one UPDATE — short
transactions preserved). `get_active_incidents()` now applies the same
all-claims overlay as `get_incident_by_id()` so the active list never
mixes projections across proposals.

### 2. Pre-side-effect authorization guard (Goal B)

Stage-callback checks happen **after** a side effect would already have
run if the lease were lost mid-stage. A single reusable check,
`ProposalExecutionService.assert_execution_lease_live(incident_id,
proposal_id)`, runs immediately before every remote side effect:

1. this attempt's heartbeat has not observed ownership loss,
2. the durable claim row still exists,
3. `state == LEASED`,
4. `lease_owner` is this worker (never caller-supplied),
5. `lease_expires_at > now`.

Store/network uncertainty raises the same typed guard error (fail
closed — uncertainty is never authorization). The orchestration layer
receives the check as an injected `before_side_effect(name)` callable
and invokes it before: `workspace.prepare`, `patch.apply`,
`validation.run`, `commit.create`, `remote.publish`, `remote.branch.create`,
`pr.discovery` (the control-plane read that decides whether to mutate),
`pr.create`, and every resume-path remote read (`remote.inspect` first).
On refusal the side-effecting function is **never invoked**; the typed
failure flows through the existing classification and owner-gated
persistence; no silent reclaim occurs in the running worker (reclaim =
a new attempt).

**Honest semantics:** a successful guard means only that the durable
control plane reports live ownership *at that instant*. External
operations are not atomic with the database lease — heartbeat renewal
during the operation, owner-gated post-stage persistence, remote
reconciliation and fail-closed sequencing remain as defence in depth.
Exactly-once external execution is explicitly not claimed.

### 3. Post-create pull request identity (Goal D)

After `create_pull_request` succeeds, a bounded re-discovery must return
the created PR proving **exact identity**: repository == proposal
repository, head == the deterministic branch, `head_sha` == the executed
commit, base == the allowed base, open and unmerged, exact URL match.
Title/body/number/URL alone never authorize; the body hash is only
corroboration. Wrong SHA, wrong repository, wrong base, closed/merged or
malformed results raise typed failures and the operation fails closed —
never a second PR, retarget, force-push or auto-merge — while the
pre-existing discovery-before-create reuse policy (zero second creates
on lost responses) is unchanged.

### Honest limitations (Phase 6.2.1B)

- Concurrent multi-writer expiry CAS races are exercised on SQLite
  through the same portable SQLAlchemy statement path; PostgreSQL
  concurrency is **untested**.
- The guard bounds the window; it does not make external side effects
  atomic with lease state (no exactly-once claim).
- Postgres must be treated as external evidence: the claims table has
  no migration — schema remains code-defined (`metadata.create_all`).

## Phase 6.2.1C — Finish CAS atomicity & post-create PR uniqueness

Two correctness gaps from the 6.2.1B review, no architecture change:

- `finish_execution_lease()` raises the coordination-race error when the
  final claim CAS affects zero rows so the whole transaction (proposal
  terminal state, mirrors, failure fields, evidence) rolls back — a
  stale worker whose lease was replaced can never commit through that
  path. Existing typed failure handling and owner-gated semantics are
  unchanged; this is stale-writer isolation, **not** exactly-once.
- Post-create PR verification requires **exactly one** discovered PR for
  the deterministic head/base pair, then verifies that sole PR's exact
  URL, head repository, head branch, executed SHA, allowed base,
  open/unmerged state, and draft status. Duplicates, non-draft results,
  mismatches or malformed discovery all fail closed with at most one
  create ever issued; discovery-before-create reuse is untouched.

Known limit: deterministic interleavings are proven on SQLite; concurrent
PostgreSQL writers remain untested in CI.

## Phase 6.2.2 — Hardened remediation execution sandbox

The remediation pipeline previously executed validation (repository
test/build workloads) on the incident-service host trust boundary. As of
Phase 6.2.2 that workload runs only inside a short-lived constrained
container:

```
verified proposal → before_side_effect("validation.run") lease guard
  → build sandbox run plan (pure policy) → docker run (pinned image,
  network=none, non-root, read-only, cap-drop ALL, no-new-privileges,
  seccomp, pids/memory/cpu bounds, single workspace bind)
  → bounded result → container destroyed → existing owner-gated
  durable progress → existing orchestration continues
```

Key invariants:

- **No unsandboxed fallback.** `RemediationValidationRunner` requires
  an injected `ValidationSandboxPort`; construction without one raises.
  Production wiring uses `ContainerValidationSandbox.from_environment()`.
  Failures are typed (`ValidationSandboxUnavailableError` /
  `ValidationSandboxConfigurationError` / `ValidationSandboxResultError`)
  and fail closed. `LocalProcessValidationExecutor` exists only as an
  explicit test seam.
- **No host secrets in the sandbox.** Environment = constant
  `SANDBOX_ENV_ALLOWLIST` only; tokens/DB/Redis/JWT/cloud credentials
  are never passed via env, mounts or default locations.
- **Filesystem bounded.** Exactly one bind mount: the ephemeral
  per-attempt workspace at `/workspace`. No host root, home, `.ssh`,
  docker socket, `/proc`, `/sys`.
- **Network disabled by default** (`--network none` is the only mode
  the policy accepts; exceptions require an explicit change in
  `validation_sandbox.py`).
- **Privilege reduced:** non-root, read-only rootfs, all capabilities
  dropped, no-new-privileges, seccomp (runtime default or validated
  profile; `unconfined` forbidden), never privileged/host-network/
  host-PID.
- **Bounds:** step timeout ≤ 180s (+10s wall grace), 768 MiB memory,
  2 CPUs, 256 pids, 128 KiB output — enforced by policy validation that
  profile construction and plan generation both re-check.
- **Cleanup:** `--rm` plus unconditional best-effort
  `docker rm -f <name>` on success, timeout, command failure and
  startup failure.
- **Image:** digest-pinned (`name@sha256:...`, `--pull never`);
  floating tags are rejected. Configure via `REMEDIATION_SANDBOX_IMAGE`
  (resolve with `docker pull <tag> && docker image inspect --format
  '{{index .RepoDigests 0}}' <tag>`); unset configuration fails closed
  at execution time. Optional `REMEDIATION_SANDBOX_SECCOMP_PROFILE`.

**Corrective pass (writable-workspace gap):** the workspace bind is
`:ro` — validation observes the real Git workspace (including `.git`,
inside the same read-only mount) but cannot write the working tree,
the approved target, or Git metadata; the only writable path is tmpfs
`/tmp`. In addition, the host snapshots approved-target SHA-256, HEAD,
staged/worktree state and `.git/HEAD|index|config` digests immediately
before and after every sandboxed step and requires exact equality
(before-sandbox == after-sandbox), so a zero exit code alone never
authorizes a changed workspace. All validation-time Git reads use
`--no-optional-locks` (validation itself never rewrites `.git/index`).

Honest limitations: configuration unit tests prove the generated
runtime plan, not kernel enforcement; the real-container integration
tests (read-only denial of target rewrites and `.git` writes, plus the
isolation suite) run only where a docker runtime is available
(GitHub-hosted runners) and are honestly skipped otherwise. The claim
is deliberately narrow: the untrusted validation workload receives a
read-only view of the remediation workspace and cannot write the host
repository or Git metadata through the mounted workspace — the host
still performs controlled Git patch/commit/publish operations outside
the sandbox with the existing fixed-argv and SHA checks. The sandbox covers
the validation workload — workspace preparation, patch application and
commit remain host-side fixed-argv git operations (no repository code
execution; repository content is data, never command policy). Not
"production-safe", not "escape-proof", not exactly-once. The lease,
heartbeat, stale-writer CAS, reconciliation and draft-PR semantics from
Phases 6.2.1A/B/C are unchanged.

## Network & authentication trust boundary

* **External boundary = API gateway only.** `docker-compose.yml` publishes a
  host port for `api-gateway` (8000) and for **nothing else** - incident,
  deployment, repo, agent, monitoring and the data stores have no host
  publication and are reachable exclusively over the private compose network
  (service-name DNS). Direct external requests to internal services are
  therefore impossible in the production topology; guessing `/api/internal/*`
  grants nothing (a URL prefix is not authorization).
* **Authentication** happens at the gateway (HS256 JWT, `JWT_SECRET` is
  fail-fast `${JWT_SECRET:?}` in compose). Internal service-to-service calls
  stay inside the trusted private network - no second token system, no
  secrets in source.
* **Development:** `docker-compose.dev.yml` is an explicit, opt-in override
  that re-publishes internal ports for local debugging:
  `docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d`
* **Layered authorization:** even in-network callers must pass the
  remediation target binding (canonical repository + exact 40-hex SHA in one
  *DEPLOYED* evidence record of the same incident, with valid provenance)
  before the remediation orchestrator is even constructed.
* **Internal request trust model (no second token system):**
  * *Identity source* — only the gateway authenticates callers (HS256 JWT,
    `sub` + `roles` claims); it stamps `requested_by`/`approved_by` from
    `sub` before forwarding. Downstream HTTP APIs trust the private network
    (single-operator deployment), which is why host publication of
    internals is forbidden by the compose contract above.
  * *Credential lifecycle* — gateway JWT secret lives in the `JWT_SECRET`
    env (fail-fast `${JWT_SECRET:?}` in compose); tokens carry a 1-hour
    `exp`; rotation = set a new secret and restart the gateway (old tokens
    die immediately). GitHub verification uses `GITHUB_OAUTH_TOKEN`
    (header-only, optional for public repos).
  * *Failure behavior* — invalid/expired/bad-signature JWT → 401; wrong
    role → 403 (before any network call); downstream unreachable → 502;
    downstream answers relayed verbatim (404/409/422/403); Sentry
    webhooks without a configured secret → 503.
  * *Replay* — bearer tokens are time-boxed (1 h) but not nonce-tracked;
    short TTL is the accepted trade-off for this single-operator product.
  * *Logging* — rejected tokens are logged by reason only (never the
    secret, never the token); webhook rejections log no payload.
  * *Tests* — `api_gateway/tests/test_control_plane.py`,
    `tests/test_control_plane_e2e.py`, `tests/test_platform_smoke.py`,
    `tests/test_compose_network_boundary.py`.

## Known limits (honest)

* The `dispatch` route forwards to service hostnames
  (`repo-service:8010`, …) that only exist **inside the compose network**.
  Run a single service locally without compose and dispatches will 502 —
  that is truthful behaviour, not a bug.
* The `deployment` dispatch target has no HTTP layer (it is a Celery worker);
  it will 502 until an HTTP surface is added.
* gRPC surfaces (ports 50051–50055) are still sketch: `grpcio` is installed,
  service impls exist, but **no `.proto` files and no registered servers**
  were in the original export — left as-is.
* Postgres adapters are still mostly stubs (see each
  `infrastructure/persistence/` module); the services run on in-memory mocks
  by design until real adapters are wired.
* `gemini-3.5-flash` / `gemini-3.1-pro-preview` model ids are unverified
  upstream; the Gemini caller fails soft into templates/offline bypass.
* **SSH host-key verification** — `repo_service`'s git SSH helper disables
  `StrictHostKeyChecking`, which weakens first-contact host identity for
  *that* service's own clones. The remediation publication path does **not**
  use it (HTTPS clone + `ls-remote` SHA verification instead), so this is a
  separate, unmitigated risk in `repo_service`, recorded here rather than
  silently expanded into the remediation trust chain.
* **Validation-runner sandbox** — the remediation validation runner bounds
  commands with `shell=False`, fixed profiles, timeouts and env
  sanitation; since Phase 6.2.2 the workload executes only inside a
  digest-pinned, network-less container sandbox (no host-execution
  fallback). Untrusted patch content is still checked
  (`git apply --check` + path rules); workspace preparation, patch
  application and commit remain host-side fixed-argv git operations.
* **Two stacks exist** — the repository-root `docker-compose.yml` is the
  broad *development* stack (Postgres/Redis/Qdrant/gateway/Prometheus/
  Grafana + backend services with several host ports for local debugging).
  The **platform** topology described above is
  `devops-ai-platform/docker-compose.yml` (gateway-only host publication)
  with `docker-compose.dev.yml` as the explicit opt-in for internal ports.
  Do not confuse the two when reasoning about the trust boundary.
* **Governance (not a code fix)** — the `main` branch currently has no
  GitHub branch protection (verified via the API). Restricting direct
  pushes, requiring PR reviews and enforcing status checks is a repository
  *settings* action; it is recorded as a recommendation and intentionally
  not changed from code.

## Tests

```bash
pip install pytest
python -m pytest tests/ -v
```

Covers: JWT sign/verify/reject/expiry, gateway 401/404/502 contracts,
control-plane role matrix + identity stamping + full E2E chain,
Sentry HMAC accept/reject/unset-secret (503), provenance hash contract
(tamper/graft/unverified/over-claim), source-verification fail-closed
matrix, remediation binding attacks, SSE + WebSocket endpoints, repo
import, shared-kernel VOs/events, Celery task registration,
GitHub no-fake-PR guard, and the Phase 6.1 proposal pipeline
(event-id idempotency, monitoring producer, schema fail-closed RCA,
target binding, deterministic risk/hash, proposal endpoints + gateway
read route, reload round-trip, blocked outcomes, no-side-effect spies),
plus the live vertical slice: monitoring runtime composition →
`POST /api/internal` → consumer envelope → incident consumer →
proposal (duplicate-event, malformed-input, prompt-injection-as-data and
no-side-effect cases included).

Phase 6.2 execution adds: approval policy unit matrix (hash binding,
TTL, risk bounds, target drift, injection-as-data), execution service
gates (unapproved/tampered/stale/drift → zero side effects), failure
matrix A–I (validation/GitHub/patch failures, redaction, retry,
duplicate reconcile, concurrency invariant), controller HTTP mapping,
gateway operator routes (auth/role/stamp/relay/internal-prefix), and a
real-git integration E2E (persisted proposal → approval → execution →
local bare-origin push → draft PR, plus no-publish failure cases).

## Phase 6.3 — Evidence-driven operational analytics & remediation intelligence

`GET /incidents/analytics/summary?start=<ISO 8601>&end=<ISO 8601>`
(fastapi-app: forwarded as `GET /v1/analytics/summary` by the API gateway
behind the existing JWT `verify_token` auth + rate limit). One summary
endpoint, one application service
(`application/services/operational_analytics_service.py`) that owns
window validation and aggregation; handlers carry no SQL and no rules,
the repository port gained ONE window-bounded read
(`list_incidents_in_window`, parameterized `created_at >= start AND
created_at < end`, `ORDER BY created_at, id`, one bulk evidence query —
exactly two statements regardless of cohort size, deliberately WITHOUT
the per-incident claim overlay — no schema change).

**Window contract.** Half-open UTC `[start, end)`, at most 31 days,
service-validated (inverted/oversized/malformed → 422 with an explicit
detail). Naive datetimes are treated as UTC, aware ones normalized.
Aggregation is pure — no clock reads — so identical durable records
always produce byte-identical JSON: fixed sorts, zero-filled UTC day
buckets, integer-second timing with nearest-rank p50/p95.

**Incident-cohort semantics (not event-time analytics).** The window
selects incidents by `incident.created_at`. All RCA, remediation,
execution, and timing facts attached to those selected incidents are
analyzed as part of that incident cohort, even when child timestamps
fall outside the window (an incident created inside the window keeps a
proposal generated later; child events inside the window never pull an
out-of-window incident into the cohort).

**Metrics (durable sources only).** Incident volume (total / by UTC day /
by severity / by status) from `devops_incidents`; RCA coverage (reached /
without / malformed partition) from `kind="rca_result"` evidence
presence — never by guessing at free text; proposal outcomes from
durable `status` + `approved_at`; pipeline phases (validation, commit,
publication, pull request) as exact per-proposal partitions derived from
proposal status plus the latest `kind="remediation_execution"` evidence
`stages` notify progression (membership and `validation.completed.passed`
only); failures grouped verbatim by `last_failure_stage`. Timing exposes
exactly the two intervals where BOTH timestamps are durable and
compatible: `proposal → approval` (`generated_at → approved_at`) and
`approval → execution completion` (`approved_at →` latest execution
evidence `observed_at`).

**No fabrication.** Every response carries `data_quality.exclusions`
(fixed reason vocabulary, counters always present, zero unless stated:
missing timestamps, negative durations, incomplete executions,
malformed/unmatched evidence, out-of-window defence) and an explicit
`unsupported` manifest with BECAUSE/WOULD REQUIRE reasons:
counts by service/component (no dedicated field), RCA category
distribution (free text), rejected/expired proposal counts (never
persisted — the approval TTL only gates approval), recovery and
recurrence outcomes (no durable identity), and the five pipeline timing
intervals with no durable timestamps (`HotfixProposal.executed_at` is
never written in production).

### Honest limitations (Phase 6.3)

* Read-only analytics over incident-service records only — no
  ML/forecasting/anomaly detection, no LLM metrics, no dashboards, no
  new DB/queue/warehouse, no remediation/approval/rollback automation.
* Unauthorized-workflow outcomes (rejected/expired) and lifecycle
  outcomes with no durable field (recovery, recurrence, service
  attribution) are reported as UNSUPPORTED, never estimated.
* The gateway forwards raw parameters (single validation authority
  downstream); the gateway rate limit applies, the incident service
  itself has no in-service auth (matching every existing read route).
* §17 self-observability is a single bounded-label counter
  (`analytics_summary_requests_total{outcome}`) via the shared metrics
  facade; Prometheus is never an analytics data source.

## Phase 6.4 — Change intelligence & release verification foundation

`GET /changes/{deployment_run_id}/health?start=<ISO 8601>&end=<ISO 8601>`
(fastapi-app: forwarded as `GET /v1/changes/{deployment_run_id}/health` by
the API gateway behind the existing JWT `verify_token` auth + rate
limit; any authenticated user — aggregates expose no patch content).
One typed, read-only assessment service
(`application/services/change_intelligence_service.py`) owns correlation
and the deterministic rule evaluator; handlers carry no SQL and no
rules; persistence is the existing incident/evidence read (the Phase 6.3
window-bounded repository read — two statements, no N+1, no new table).

**What a change ↔ incident link means.** A link is an evidence-backed
association (correlation), never causal proof. Hierarchy, on durable
identifiers only:

1. `deployment_run_id` — an incident's `kind="deployment_run"` evidence
   payload records the exact deployment run id (strong basis);
2. `repository_source_sha` — exact `repository_name` + exact deployed
   `source_revision.head_sha` matching the authoritative record for that
   run (supporting basis).

The authoritative record for a run is the latest exact-id evidence
record by `(observed_at, evidence_id)` (the same deterministic winner
rule as remediation target binding). Timestamp proximity alone never
creates a link; service/component identity is never guessed from title
text. Language: linked / associated / observed after deployment — not
"caused by".

**The four decisions** (exactly these values; structured reason tokens,
no prose):

* `HEALTHY` — state `DEPLOYED`, health check `PASS`, valid platform
  provenance describing this record, complete identity, rollback absent
  or `PASS`, no unresolved linked incident, no failed linked remediation
  (reason `all_required_evidence_healthy`).
* `DEGRADED` — operational deterioration without terminal failure:
  state `ROLLBACK_PENDING`/`ROLLED_BACK` (`deployment_state_degraded`),
  ≥1 linked incident whose status is not terminal (`Fixed`/`Resolved`
  vocabulary — `linked_unresolved_incidents`), or a linked incident with
  a durable `EXECUTION_FAILED` proposal (`linked_remediation_failed`).
* `FAILED` — an authoritative failure field: state in
  {`VALIDATION_FAILED`, `DRY_RUN_FAILED`, `DEPLOYMENT_FAILED`,
  `ROLLBACK_FAILED`} (`deployment_state_failed`), health check `FAIL`
  (`deployment_health_check_failed`), or rollback `FAIL`
  (`deployment_rollback_failed`).
* `INCONCLUSIVE` — required evidence missing/untrustworthy (target SHA,
  repository, state missing/unrecognized/nonterminal, health check
  missing/`BLOCKED`/`TIMEOUT`/unknown, unrecognized rollback status,
  provenance missing/invalid). Incomplete evidence is never forced to
  `HEALTHY`, and malformed evidence is never `FAILED` without an
  independent authoritative failure field.

**Signal sources & rule semantics.** All signals are durable evidence
fields captured by the deployment-evidence collector (state,
health_check status, rollback status, provenance, artifact/plan hashes,
source SHA) plus in-cohort incident/proposal records (status, severity,
`EXECUTION_FAILED` outcomes). Rules are explicit, typed, bounded,
order-independent (fixed precedence `FAILED` > `DEGRADED` >
`INCONCLUSIVE` > `HEALTHY`, fixed reason order); no ML, LLM,
probabilistic scoring or heuristic confidence exists here.

**Observation window.** The Phase 6.3 contract verbatim: caller-
supplied UTC half-open `[start, end)`, ≤31 days (invalid/oversized →
422), identical persisted inputs + identical window → byte-identical
response. The window selects the incident cohort; deployment evidence
attached to in-window incidents defines what the assessment can know.
Unknown deployment in scope → 404.

**Explicitly unsupported** (never attempted in 6.4): automatic
rollback, canary/blue-green/Kubernetes rollout control, service-mesh or
feature-flag integration, ML anomaly detection, predictive failure
models, LLM health decisions, live Prometheus as a health source, new
event bus/warehouse/dashboard, and any mutation — the endpoint is read-
only and cannot approve, remediate, roll back, or deploy.

### Honest limitations (Phase 6.4)

* Correlation ≠ causation: linked incidents are associations on exact
  identifiers; no causal attestation is produced or implied.
* Assessments can only cover deployments that have durable
  `deployment_run` evidence inside the observation window (evidence
  lives on incidents); a change with no such evidence returns 404, not
  a synthetic HEALTHY.
* Deployment signals are the durable evidence snapshot captured at
  attach time — not a live query of the deployment service or
  Prometheus; state changes after attachment are not re-read.
* `provenance_invalid` is recorded on non-`DEPLOYED` records by design
  (platform provenance is authoritative for `DEPLOYED`); it is a data-
  quality fact and never drives `FAILED` alone.

## Phase 6.5 — Change-aware live release verification

`GET /changes/{deployment_run_id}/live-health?start=<ISO 8601>&end=<ISO 8601>[&baseline_deployment_run_id=…]`
(fastapi-app: forwarded as `GET /v1/changes/{deployment_run_id}/live-health`
by the API gateway behind the existing JWT `verify_token` auth + rate
limit; any authenticated user — no patch content). This is the OBSERVE
layer following Phase 6.4's JUDGE layer: 6.4 answers whether **durable
evidence** says a release is healthy; 6.5 answers whether **live
telemetry attributable to that exact release** supports the same
conclusion. One response is the combined read model:
`{"durable_assessment": <unchanged Phase 6.4 result>, "live_assessment":
<Phase 6.5 result>}`. Phase 6.4 decision semantics are consumed
verbatim, never re-evaluated.

**Bounded, read-only Prometheus access** (extend-the-existing-client,
no new metrics stack): `PrometheusScraperClient.query_range_metric()`
performs a fixed-timeout (5 s) read-only GET against
`/api/v1/query_range` with **predefined query templates only** — no
arbitrary PromQL ever reaches Prometheus, from any HTTP surface. Fixed
bounds: ≤31-day window, ≤500 points per query (minute-aligned step),
≤10 000 samples per response, and exactly **one query per SLI per
assessment** (identical call count with or without a baseline — series
and sample volume cannot fan out into N+1 queries). Fail-closed: timeout,
connection failure, non-200, malformed JSON/envelope, unexpected
resultType, non-finite values, or sample-cap overflow all become
structured data-quality gaps — never partial data. The existing
`query_instant_metric()` behavior is preserved unchanged.

**Response-body bound (corrective hardening).** The range-query client
buffers at most `MAX_RESPONSE_BYTES = 4 MiB` per response: an oversized
declared `Content-Length` is refused before any body read, and
unknown-length/chunked bodies are read in bounded 64 KiB chunks with
the same ceiling (at most limit + 1 probe byte ever buffered), so an
oversized body is never JSON-decoded. This bounds **this client's
response buffering** together with the independent
`MAX_RESPONSE_SAMPLES = 10 000` logical-result limit — it is not a
claim of absolute Prometheus or process memory safety.

**Exact release attribution (the authoritative telemetry fields).** A
telemetry series is attributable to a release **only** by exact string
match of its labels against the Phase 6.4 authoritative deployment
record:

1. label `deployment_id` == the deployment run id, **or**
2. label `source_sha` == the exact 40-hex source SHA.

Nothing else counts. Label `service_version` is deliberately not
authoritative (durable identity carries no version string to match —
accepting it would be guessing). Timestamps are never consulted:
samples that merely occur inside the release's time window are **not**
attributed to it.

**Release identity carrier (Phase 6.5.1).** The backend runtime exposes
exactly one low-volume info metric,
`devops_release_identity_info{deployment_id,source_sha} 1`, populated
at startup from two operator/runtime environment inputs —
`DEVOPS_DEPLOYMENT_ID` (exact Phase 6.4 deployment run id) and
`DEVOPS_SOURCE_SHA` (exact lowercase 40-hex SHA), both validated
fail-closed in `backend/app/release_identity.py` (blank, uppercase,
short, prefixed, whitespace or control-character values are rejected
and expose **no** series — never fabricated). Both SLI templates
inherit those two labels onto their results via a vector join on the
scrape-target identity `on(job, instance)` with
`group_left(deployment_id, source_sha)`, so attribution survives
aggregation while release identity stays on the single carrier series
instead of multiplying across every request sample. No carrier series
→ empty join → `attribution_unavailable` → INCONCLUSIVE.

**Runtime identity injection (Phase 6.5.2).** The carrier's inputs are
no longer merely operator-supplied: the deployment engine now binds them
at the real workload-runtime boundary. When a run reaches actual
execution (`DeploymentEngine.execute` → `kubectl apply`, gated by
`DEPLOYMENT_EXECUTION_ENABLED=true`), the manifest's container env
receives `DEVOPS_DEPLOYMENT_ID` = the run's own persisted `id` and
`DEVOPS_SOURCE_SHA` = that same record's verified
`source_revision.head_sha` (canonical lowercase 40-hex, independently
source-verified before the run existed) — both straight from the trusted
execution context, never from request payloads or client spec fields.
Client-planted `DEVOPS_*` entries in the submitted manifest are replaced
(authoritative record wins); an unusable identity injects nothing
(fail-closed — no fallback, no fabricated identity). The binding happens
in `deployment_service/.../release_identity_injection.py` immediately
before `kubectl apply`, i.e. at the point the real workload runtime is
created — so an executed deployment's runtime is exactly compatible with
the Phase 6.5.1 carrier contract.

**Supported SLIs (fixed catalog, real telemetry only).**

| SLI | Predefined query | Backed by |
|---|---|---|
| `request_rate` | `sum by (job, instance, deployment_id, source_sha) (rate(devops_api_requests_total[5m]) * on(job, instance) group_left(deployment_id, source_sha) devops_release_identity_info)` | backend gateway `Counter` (`backend/app/main.py`), scraped via `monitoring/prometheus.yml`, identity joined from the carrier metric |
| `cpu_saturation` | `avg by (job, instance, deployment_id, source_sha) (rate(process_cpu_seconds_total[2m]) * on(job, instance) group_left(deployment_id, source_sha) devops_release_identity_info)` | default `prometheus_client` process collector on the same scrape target, identity joined from the carrier metric |

Error-rate and latency SLIs are intentionally absent: no error-labeled
or duration-histogram metric exists in this repository's telemetry
path, and inventing one would fabricate data.

**Deterministic decision model** (explicit rules, no ML/LLM/
probabilistic scoring; fixed precedence `FAILED > DEGRADED >
INCONCLUSIVE > HEALTHY`):

* `FAILED` — `cpu_saturation_critical`: attributable in-window mean ≥
  0.90 cores.
* `DEGRADED` — `cpu_saturation_warning`: attributable mean ≥ 0.70
  cores; or `request_rate_dropped_vs_baseline`: candidate attributable
  mean < 50 % of an explicitly requested, resolvable, attributable
  baseline mean.
* `INCONCLUSIVE` — any data-quality gap: telemetry unavailable,
  malformed response, unsupported metric, insufficient attributable
  samples (< 3 per SLI), attribution unavailable, or a requested
  baseline that cannot be resolved/attributed (`invalid_baseline`).
* `HEALTHY` — `all_required_signals_healthy`: both SLIs attributable,
  ≥ 3 in-window samples each, within policy, no gaps.

**Baseline/reference comparison.** The optional
`baseline_deployment_run_id` parameter names the reference release
**explicitly** — it must resolve to durable Phase 6.4 evidence inside
the same window and its telemetry must attribute to that identity, or
the assessment reports `invalid_baseline` (never “whatever was live
before”). Without the parameter, only the absolute SLI policies are
configured and evaluated; no implicit baseline is ever chosen.

**Fail-closed / data-quality contract.** Missing data is never zero
(an unevaluable SLI reports `value: null` with its true sample count);
malformed data is never a success or failure signal; time proximity
never creates correlation. The `data_quality.exclusions` block always
carries the full fixed vocabulary (`telemetry_unavailable`,
`malformed_response`, `unsupported_metric`, `insufficient_samples`,
`attribution_unavailable`, `invalid_baseline`) with counts. HTTP
mapping: invalid/oversized/inverted window → 422 (Phase 6.3 validator,
single authority); unknown deployment → 404; **every telemetry failure →
200 with `decision=INCONCLUSIVE`** (a 5xx would misrepresent missing
data as an operational failure).

**Explicitly unsupported** (never attempted in 6.5): canary/progressive
traffic routing, blue/green switching, Kubernetes rollout
orchestration, automatic rollback, autonomous remediation, ML/LLM
release judgments, user-defined PromQL, dashboards/UI, new database
schema, event bus or warehouse. This endpoint is read-only and cannot
shift traffic, roll back, or act on its decision.

### Honest limitations (Phase 6.5)

* Live verification verifies — it never acts: no traffic shifting,
  rollback, or remediation exists on this surface (CONTROL/ACT are
  later phases).
* Attribution now flows through the Phase 6.5.1 identity carrier,
  bound at execution by Phase 6.5.2: runs executed through the real
  deployment path receive `DEVOPS_DEPLOYMENT_ID` + `DEVOPS_SOURCE_SHA`
  from their own authoritative record at `kubectl apply` time
  (request-counter samples stay free of release labels). Identity is
  absent — and assessments correctly return
  INCONCLUSIVE/`attribution_unavailable` — whenever no run has executed
  on that target, execution is disabled, or the compose operator has
  not passed the variables through; the join, attribution and decision
  rules are exercised end-to-end against the mocked Prometheus
  boundary.
* Telemetry is read live at request time from Prometheus (when
  reachable); it is not persisted by this path, and the verification
  window must cover both candidate and baseline durable evidence for
  baseline comparison to resolve.
* The baseline window constraint is intentional fail-closed behavior:
  a baseline whose evidence sits outside the window yields
  `invalid_baseline`, not a silent substitute.
