# Phase 8 — Control-Plane Architecture & Reconciliation

Status vocabulary for claims in this document (§43 of the Phase 8 brief):
**implemented** (code exists), **tested locally** (suite green in dev sandbox),
**tested in containers**, **tested in CI**, **not verified**, **known limitation**.

## 0. Branch & baseline note (honest deviation log)

- Session branch: `arena/01a0cf63-autonomous-devops-engineer`
  (this Arena session is fixed to that branch; the brief's requested
  `dev/phase-8-control-plane-hardening-v1` cannot be created here — the PR
  body records this deviation).
- Re-checked `main` at Phase 8 start: `7b30a56d2bfd06798c0a90023acd1c6bd5cd3420`.
  It is an **unrelated root commit** (no parent, no common ancestor with the
  session line whose root is `f7f8513`). PR #6 (`integration/remediation-platform-reconciliation`)
  and PR #7 (this branch) both target `main`; neither is auto-merged.
  PR #2/#4/#5 branches are untouched.
- Phase 8 work therefore builds on the session line
  (`97b8ec4` → Phase 8 commits). Divergence from `main` is reported in the
  implementation report; cherry-picking from PR #6 is treated as a
  source-of-changes decision, per §2.

## A. Component ownership (who owns what)

| Concern | Owner | Evidence |
| --- | --- | --- |
| Incident lifecycle (creation, evidence attach, triage/RCA status) | `devops-ai-platform/incident_service` domain aggregate `IncidentAggregate` | `domain/aggregates/incident.py` |
| Evidence records (incident evidence) | `incident_service` aggregate + `IncidentEvidence` entity, persisted by repository adapter | `domain/entities/incident_evidence.py` |
| RCA boundary (analysis → `RootCauseAnalysis` evidence) | `incident_service` `POST /{incident_id}/rca` + `rca_analyzer` / `rca_evidence_pack` | `presentation/rest/controllers.py:203` |
| Remediation **proposal** generation + validation + hash | `incident_service` `proposal_generation_service` (+ `HotfixValidationService`, `compute_proposal_hash`) | `application/services/proposal_generation_service.py` |
| **Approval** (PROPOSED → APPROVED) | `incident_service` `proposal_approval_service`; gateway stamps `approved_by` = JWT `sub` | `proposal_approval_service.py`, `api_gateway/routers/control_plane.py:280` |
| **Execution** preflight + orchestration (APPROVED → EXECUTING → PR_CREATED) | `incident_service` `proposal_execution_service` → `remediation_orchestration_service` / workspace / commit / patch executor / validation runner | `proposal_execution_service.py` |
| Git workspace (clone/checkout/branch/commit/push) | `incident_service` `remediation_workspace_service` + `remediation_commit_service` | application services |
| Git publication (deterministic branch `automation/...`, remote SHA verify) | `remediation_commit_service` / workspace push path | tests `test_remediation_workspace_push.py` |
| GitHub API owner (PR create/reconcile) | `incident_service/infrastructure/source_provider/github_pr_client.py` (typed failures) | `github_pr_client.py` |
| Deployment evidence (trusted target: repo + 40-hex SHA) | `incident_service/infrastructure/deployment/deployment_evidence_collector.py` + `remediation_target_binding.py` | binding rule §5 below |
| Authentication (HS256 JWT, expiry, roles) | `api_gateway/core/auth.py` (`verify_token`, `require_operator`) | gateway-only; no second auth system |
| Persistence | `incident_service/infrastructure/database/postgres_incident_repo.py` — SQLAlchemy `create_all`, tables: `incidents`, `evidence`, `progressive_release_gate_evaluations`, `progressive_rollout_stages`, `execution_claims` | durable (SQLite locally / Postgres in compose) |
| Audit / observability | proposal/execution services + `operational_analytics_service`; structured transition events (§26) are a **Phase 8 gap → see §G** | |
| Legacy compatibility | `backend/` (FastAPI + Celery: repositories/analyze, incidents/investigate, legacy deploy) | **no** GitHub/Git/subprocess publication code found (`rg` clean) |

### Ownership rule (§1)

`devops-ai-platform/` is the **canonical control plane**. `backend/` is a
**legacy/compatibility subsystem**: it may keep working, but it must not gain
any new remediation-approval-execution capability. Any future remediation
feature is implemented once, in `devops-ai-platform/incident_service`.

## B. Which API is canonical

The canonical remediation control path (gateway → incident service):

```text
POST /v1/incidents/{incident_id}/proposal           → generate + persist PROPOSED (or BLOCKED)
GET  /v1/incidents/{incident_id}/proposal            → read persisted proposal state
POST /v1/incidents/{incident_id}/proposal/approve    → operator approves EXACT proposal_hash
POST /v1/incidents/{incident_id}/proposal/execute    → preflight + guarded execution → PR_CREATED
```

Supporting incident-side inputs: `POST /{incident_id}/rca` (RCA evidence),
deployment evidence collection, proposal GET on the incident service
(`/changes/...` gate/rollout routes remain evidence/rollout reads only).

### Decision for `POST /v1/incidents/{incident_id}/remediation`

**Chosen option: (1) compatibility shim that obeys the canonical state machine.**

Why not (2) removal: repository usage shows the route is referenced by
authorization/E2E tests and exposed by the gateway; the brief allows
deprecation only "where repository usage proves it is safe", and a shim keeps
callers working while eliminating the bypass.

Why a shim is required at all: today the route

- accepts caller-supplied `repository_slug`, `source_sha`, `target_filepath`,
  `patch`, `base_branch`, `pr_title`, `pr_body`,
- does bind the target to the incident's DEPLOYED evidence and validates the
  patch (403/422), and requires operator role at the gateway,
- **but executes the orchestrator directly**: no persisted proposal hash, no
  PROPOSED → APPROVED operator transition, no execution preflight, and it
  persists the proposal *after* execution.

That is a second destructive path capable of bypassing approval (§1/§3).

**Shim contract (Phase 8 work):** the route keeps its request shape, keeps
404/403/422 semantics, but instead of executing it **creates the canonical
persisted proposal** (validated, hashed, `status=PROPOSED`, incident promoted
to `RemediationProposed`) and returns the proposal identity plus the required
next steps (approve exact hash → execute). No Git/GitHub side effect may occur
on this route afterwards. Existing route tests are updated to complete the
canonical journey (approve → execute) — the bypass is closed, not preserved.

## State machines (as-is, formalized)

### Proposal lifecycle

```text
            generation                     operator            execution preflight
  (no proposal) ────────► PROPOSED ───────────────► APPROVED ─────────────────────► EXECUTING
        │                   │  ▲                      │        (fail → back to        │
        │ validation fail   │  │ documented retry     │         APPROVED with          │
        ▼                   │  │ (EXECUTION_FAILED ◄──┼──────── EXECUTION_FAILED)     ▼
      BLOCKED ──────────────┘  │                          │                      PR_CREATED
                               └──────────────────────────┘ (idempotent reconcile on re-execute)
```

Rejected transitions (tested): `BLOCKED → APPROVED`, `BLOCKED → PR_CREATED`,
`PROPOSED → PR_CREATED`, `PR_CREATED → APPROVED`, `PR_CREATED → PROPOSED`,
`APPROVED → PROPOSED`.

Operational states beyond the four brief states, **explicitly documented**
(they pre-date Phase 8 and are covered by tests, so they are documented here
rather than invented as recovery states):

- `EXECUTING` — durable claim/lease held by exactly one worker.
- `EXECUTION_FAILED` — preflight or side-effect failure released the claim;
  re-execute is permitted and re-runs the full preflight.

### Incident lifecycle

```text
Raised → Triage → Investigating → RootCauseFound → RemediationProposed → RemediationPRCreated
```

As-is deltas to implement in Phase 8 (currently **implemented** partially):

| Required transition | As-is | Phase 8 action |
| --- | --- | --- |
| `Raised → Triage` | implemented (`move_to_triage`, silent no-op elsewhere) | keep + reject illegal calls |
| `Triage → Investigating` | **missing** (no code sets `Investigating`; the RCA endpoint jumps `Triage → RootCauseFound` in one call) | add explicit transition + wire RCA flow through it |
| `… → RootCauseFound` | implemented (guards `Triage`/`Investigating`) | unchanged |
| `RootCauseFound → RemediationProposed` | implemented on verified proposal attach; BLOCKED proposals never promote | unchanged |
| `RemediationProposed → RemediationPRCreated` | **missing** (execution never promotes the incident) | add guarded transition on PR_CREATED persistence |
| invalid transitions | some raise `ValueError`, some silently no-op | make rejection explicit and tested (§40 matrix) |

`RemediationVerified` (pre-existing extra state used by
`attach_verified_patch`) is retained for compatibility and documented as
outside the brief's core chain.

## Trust boundary for deployment targets (§5, unchanged, tested)

```text
same incident
+ DEPLOYED evidence with valid provenance
+ canonical owner/repository from evidence
+ exact 40-hex lowercase source SHA
= eligible remediation target        otherwise → proposal BLOCKED / 403
blocked_reason includes MISSING_DEPLOYED_TARGET_EVIDENCE when evidence is absent
```

Caller input never selects repository or SHA for execution (execution request
carries only `incident_id`, `proposal_id`, `proposal_hash`).

## Security gates inventory (§8/§9/§11/§25)

| Gate | Status |
| --- | --- |
| HS256 JWT, expiry, roles, malformed → 401 | implemented (`api_gateway/core/auth.py`) |
| Wrong role → 403 before downstream | implemented (`require_operator` on approve/execute/remediation) |
| `approved_by`/`requested_by` overwritten with JWT `sub` | implemented (gateway forwards) |
| Proposal hash recomputed + compared on approve/execute | implemented (`compute_proposal_hash`, approval + execution services) |
| Execution preflight order LOAD → AUTH → INTEGRITY → PROVENANCE → VALIDATION → EXECUTION | implemented (`proposal_execution_service`) |
| Caller cannot supply repo/SHA/patch to execute | implemented (execute request = ids only) |
| Single-file patch policy, traversal/absolute/multi-file rejection | implemented (`HotfixValidationService`, patch policy errors → 422) |
| Deterministic head branch, base allowlist (default `main`) | implemented in execution policy — re-verified during Phase 8 test pass |
| Real-or-absent PR URL (typed GitHub failures) | implemented (`github_pr_client` typed failures; recovery E2E exists) |
| Network boundary: only gateway publishes a host port in production compose | implemented + tested (`docker-compose.yml` comment, `tests/test_compose_network_boundary.py`) |

## Persistence inventory (§15)

Durable (SQLAlchemy, restart-safe): incidents, evidence, proposals (JSON on
incident row with per-proposal mapping), proposal hashes, statuses, approval
identity/timestamps, PR URL, execution timestamps, execution claims/leases
(`execution_claims` table).

Process-local (known limitations, to be confirmed in the report): in-process
locks (`threading`) as a *secondary* guard alongside durable claims; any
remaining in-memory dedup cache found during the audit will be listed
explicitly rather than claimed durable.

## E2E test inventory (existing, will be extended — §28–§35)

- `tests/test_control_plane_e2e.py` — gateway contract coverage
- `tests/test_proposal_pipeline_e2e.py` — proposal generation/PROPOSED
- `tests/test_proposal_execution_e2e.py` — guarded Git publication
- `tests/test_execution_recovery_e2e.py` — external success + local failure (§21)
- `tests/test_deployment_to_remediation_e2e.py` — evidence-bound target
- `tests/test_compose_network_boundary.py` — §24
- application tests: approval, execution, lease coordination/liveness, patch
  executor, orchestration, workspace, commit, validation runner

Phase 8 adds: the 30-step milestone happy path, dual blocked paths, tamper,
stale-target, restart-recovery, true concurrent execution race, `/remediation`
shim behavior, incident state-matrix rows, and failure-matrix regressions —
each at the smallest fitting level (§39).

## Gap register (work items for this phase)

1. `/remediation` shim conversion (close the approval bypass) + tests.
2. Incident lifecycle: `Investigating` entry, `RemediationPRCreated` promotion,
   explicit rejection of illegal transitions + §40 matrix tests.
3. Milestone E2E (§28) and blocked-path E2E (§29) as single deterministic tests.
4. Tamper (§30), stale target (§31), restart (§32) regression tests.
5. True concurrency race against the persistence boundary (§18).
6. Structured transition events with bounded correlation ids; no secrets logged (§26).
7. Docker Compose control-plane flow + induced downstream failure (§33/§34).
8. `docs/PHASE-8-IMPLEMENTATION-REPORT.md` (§44) + hostile self-audit (§45).
9. Clean-room run from a pristine checkout (§36) + secret audit (§37).
