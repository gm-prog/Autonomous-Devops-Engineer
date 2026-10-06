# Phase 8 — Implementation Report

Status vocabulary (binding for every claim below): **implemented**,
**tested locally**, **tested in CI**, **known limitation**, **not
verified**. Nothing in this report is called "production-ready", and
delivery/execution is never described as "exactly-once" — the platform's
model is **at-least-once + idempotency + CAS + lease + reconciliation +
fail-closed**.

> Note on Phase 8.0: the 8.0 report section is still pending from the
> previous phase (its architecture reconciliation lives in
> `docs/phase-8-control-plane-architecture.md` and its CI evidence is the
> green run set recorded there). This file is created now because
> Phase 8.1 (§47 of the 8.1 brief) requires it; the 8.0 section will be
> back-filled by the 8.0 owner scope, and no 8.0 claims are invented here.

---

## Phase 8.1 — Remediation Bypass Elimination & Durable Aggregate
Concurrency Control

Branch: `arena/01a0cf63-autonomous-devops-engineer` (session-fixed; the
brief's `dev/phase-8-control-plane-hardening-v1` cannot be created from
this session — recorded deviation). Baseline before the phase:
`3d87007db82f4ca11f207462986d4d54c74cce3d` (re-verified == origin).
`main` remains the unrelated root `7b30a56d2bfd06798c0a90023acd1c6bd5cd3420`.
PRs #1/#2/#4/#5/#6 untouched; PR #7 carries this phase.

### Invariants delivered

**A — REMOVE BYPASS (implemented, tested locally).**
`POST /v1/incidents/{id}/remediation` is now a compatibility shim:
authorize (evidence binding, operator role at the gateway) → readiness
precondition (RootCauseFound/RemediationProposed + persisted RCA
evidence, else 409) → trusted target via
`resolve_authoritative_deployment_target` → canonical proposal through
the existing `HotfixValidationService` / `compute_proposal_hash`
(no duplicated validation) → persist PROPOSED (unsafe patch → persisted
BLOCKED, 422) → 200 response with proposal identity, trusted
repository/source_sha, and `next_step: approve exact hash → execute`.
Legacy fields are accepted and never authoritative. The handler contains
no clone/checkout/apply/commit/push/branch/PR/deploy logic and never
constructs the orchestrator — spy-proven in tests (provider
`assert_not_called`, `RemediationOrchestrationService.execute`
`assert_not_called`).

**B — PREVENT STALE OVERWRITE (implemented, tested locally).**
`IncidentAggregate` carries a durable monotonic integer `version`:
creation = 0, each successful update +1 exactly once, unchanged on
reject/fail. Every write is gated by
`UPDATE … WHERE id = :id AND version = :expected` + rowcount (the SQL
predicate is the correctness gate; no SELECT-compare-UPDATE, no N+1).
0 rows → typed `IncidentConcurrencyConflict` (incident id + expected
version only) → full transaction rollback before evidence/proposal
writes → HTTP 409 `incident_concurrency_conflict`. No `force` flag, no
auto-reload-retry for lifecycle/security writes, no timestamps/UUIDs as
versions. Idempotent migration: `create_all` for fresh databases plus a
single `_ensure_version_column` ALTER for legacy ones — no table is ever
dropped or recreated; proposals/evidence/claims are preserved.
Details: `docs/phase-8-concurrency-model.md`.

**C — truthful conflicts (implemented).** Conflicts surface as 409 with
a machine-readable error key; structured events
(`incident.write_conflict`, `incident.version_incremented`,
`incident.version_initialized`, `remediation.compatibility_shim`,
`proposal.regeneration_conflict` upstream) carry bounded ids only.

**D — lease/claim preserved (implemented, tested locally).**
`claim_execution_lease` / `finish_execution_lease` keep their CAS
predicates (no `version` in the claim predicate — the two CAS layers
cannot fight); the terminal transaction (proposal PR_CREATED +
incident promotion + claim FREE + evidence + `version + 1`) remains one
transaction. Audit: all five `devops_incidents` write sites are
version-aware (`save_incident` insert/update, claim's proposals write +
version statement, finish's terminal UPDATE).

### Mandatory tests — status and evidence

| Brief item | Status | Evidence |
| --- | --- | --- |
| §7 stale regeneration (approve @N+1, stale save 409, APPROVED persists) | tested locally | `StaleRegenerationTests::test_stale_regeneration_cannot_clobber_approved_proposal` |
| §8 stale matrix (stale RCA/approval-shaped writers, failed txn clean, reload=latest, 2 readers 1 writer) | tested locally | `StaleWriteMatrixTests` (3 tests) |
| §10 approval race (idempotent-same vs typed conflict, one durable approval) | tested locally | `ApprovalAndRaceTests::test_concurrent_approvals_preserve_single_approved_state` (real threads + Barrier) |
| §11 regen-vs-execution race, winner lifecycle durable, terminal txn one unit | tested locally | `RegenerationVsExecutionRaceTests` (both interleavings) |
| §12 RCA-shaped stale write vs approval | tested locally | `ApprovalAndRaceTests::test_rca_shaped_stale_write_vs_approval` |
| §17/§18 real concurrency (threads + Barrier, no sleeps) | tested locally | `RealThreadRaceTests` (4-writer race; 2-reader stale race); SQLite vs PostgreSQL guarantee documented in `phase-8-concurrency-model.md` §5 |
| §19 stale reload assertions | tested locally | `VersionLifecycleTests::test_reload_returns_latest_version_and_state` |
| §21 two concurrent legacy `/remediation` → one proposal, no execution | tested locally | `RealThreadRaceTests::test_two_concurrent_legacy_remediation_calls_one_proposal` |
| §23 migration (fresh/legacy/rerun, data preserved) | tested locally | `MigrationTests` (3 tests) |
| §26 legacy→PROPOSED→restart→approve→execute→PR_CREATED; repeat cannot reset | tested locally | `tests/test_deployment_to_remediation_e2e.py::test_phase81_restart_approve_execute_then_cannot_reset` (real approval + real execution service, orchestrator faked only at the documented factory seam) |
| §27 concurrent approve-vs-regenerate E2E | tested locally | `tests/test_deployment_to_remediation_e2e.py::test_phase81_concurrent_approve_vs_regenerate_e2e` |
| §35/§36 shim cannot approve / compat-field abuse | tested locally | `RemediationShimCompatibilityTests` (`test_shim_cannot_self_approve`, `test_legacy_execution_fields_do_not_execute`, plus hidden-bypass and repeated-shim identity tests) |
| §37 stale version across restart | tested locally | `VersionLifecycleTests::test_stale_version_across_restart` |
| shim mandatory tests 1–6 | tested locally | `RemediationAuthorizationTests` (spy-proven: valid→PROPOSED, invalid→403, unsafe→422 BLOCKED, →approve→APPROVED, execute-never-called) |
| replace tests expecting `/remediation→PR` | done | `test_remediation_authorization.py`, `tests/test_control_plane_e2e.py`, `tests/test_deployment_to_remediation_e2e.py` rewritten to shim semantics; full-chain test renamed `…_shim_stops_at_proposal` |

### §39 — actual local battery numbers (this run)

Scope labels matter: each row names the exact command **and** working
directory. Rows matching a CI job were executed locally with that exact
command (GitHub Actions job logs are not retrievable through the API in
this environment, so CI evidence is the per-job conclusion recorded in
§40/PR #7, not a log-quoted count). Superset rows are broader local
scopes and are **not** CI jobs. _(Corrected during Phase 8.2 §18: an
earlier version of this table labeled a `devops-ai-platform/tests/`
run as the "Backend" CI job — the Backend job runs in `backend/` and
executes `backend/tests/` = 49.)_

| Suite (scope label) | Exact command + cwd | Result |
| --- | --- | --- |
| Incident CI job (35 unittest modules) | `python -m unittest <the 35 modules in ci.yml>` in `devops-ai-platform/` | **545 tests, OK, 3 skipped** |
| Backend CI job | `python -m pytest tests/ -v` in **`backend/`** | **49 passed** |
| Platform CI job | `python -m pytest tests/ deployment_service/tests -v` in `devops-ai-platform/` | **256 passed, 109 subtests passed** |
| API gateway CI job | `python -m pytest api_gateway/tests -v` in `devops-ai-platform/` | **71 passed, 42 subtests passed** |
| superset: application+presentation | `pytest incident_service/application incident_service/presentation` in `devops-ai-platform/` | **468 passed, 3 skipped, 71 subtests passed** |
| subset (not a CI job): platform tests dir alone | `pytest tests/` in `devops-ai-platform/` | **169 passed, 75 subtests passed** |
| Phase 8.1 concurrency module | `pytest incident_service/test_incident_concurrency.py` | **18 passed** |

Prior-phase reference (commit `3d87007`): incident 519 / gw 71+42 /
platform 254+109 / tests-scope growth as recorded then. Growth here is
the new Phase 8.1 tests; no test was deleted.

### §40 — CI

`ci.yml` incident job updated from 34 → **35 unittest modules** (adds
`incident_service.test_incident_concurrency`) and its step name updated
to match. Exact-SHA GitHub Actions run IDs and per-job conclusions for
the final push are recorded in **PR #7's description** (kept updated
after each run) — run IDs are written there rather than fabricated in
this file before the runs exist. Claim rule: no "CI green" statement
appears anywhere without an exact run id + SHA + job conclusions.

### §41 — commits

Five focused commits, in order:
1. `fix(control-plane): close legacy remediation execution bypass with proposal shim`
2. `feat(incident): durable aggregate version CAS with typed 409 conflicts`
3. `test(incident): stale-write, race, restart and migration matrix`
4. `test(control-plane): shim semantics for legacy authorization and e2e suites`
5. `docs(phase-8): concurrency model, architecture update, implementation report`

### §46 — hostile questions (Q1–Q8) with automated evidence

1. **Does the legacy route still execute anything?** No.
   `RemediationAuthorizationTests::test_valid_exact_pair_produces_proposed_shim_without_execution`
   asserts provider not called, `execute` not called, no PR/commit/branch
   fields, `executed: false`. Same proven at gateway level
   (`test_control_plane_e2e` full-chain) and HTTP level
   (`test_http_deployment_reaches_remediation_authorization`).
2. **Can legacy/compat request fields (`base_branch`, `pr_title`,
   `pr_body`, `validation_profile`, …) force approval or execution?**
   No — `test_legacy_execution_fields_do_not_execute` sends hostile
   values and still gets PROPOSED with zero orchestrator calls;
   security identity comes only from evidence (`source_sha` normalized
   from the bound deployment record).
3. **Can the shim approve itself or fake an approval hash?** No —
   `test_shim_cannot_self_approve` asserts `approved_by`/`approval_hash`
   empty after intake; approval is a separate endpoint with its own
   policy (§3.8 Test 4 approves through `ProposalApprovalService`).
4. **Are conflicts masked (HTTP 200 / `success=true` on a stale write)?**
   No — every stale path raises `IncidentConcurrencyConflict` → REST
   409 `incident_concurrency_conflict`; tests §7/§8/§10/§11/§12/§17/§18
   assert the typed error and the untouched persisted state.
5. **Is `version` a timestamp/UUID/client token, or is there a
   `force=True` bypass?** No — `version` is an `INTEGER NOT NULL DEFAULT 0`
   column advanced only by the CAS statements (all five write sites
   audited); `grep` shows no force/override parameter; migration test
   asserts the column definition itself.
6. **Does migration destroy data or fail on re-run?** No —
   `MigrationTests` proves: fresh column creation (default 0), legacy
   database ALTER-upgrade with incident/proposal/evidence/claim payloads
   readable byte-identical afterwards, and idempotent rerun (single
   column, counts unchanged). No DROP/CREATE of existing tables occurs.
7. **Do version-CAS and the execution lease CAS fight each other?** No —
   the claim predicate contains no `version`; §11 tests run
   claim → regeneration → finish and assert exactly-once version
   accounting with the claim row landing FREE in the same terminal
   transaction (or a fully rejected write — never a torn mix).
8. **Is anything claimed "exactly-once"?** No — delivery/execution
   claims are at-least-once + idempotency + CAS + lease + reconciliation
   + fail-closed, stated verbatim in `phase-8-concurrency-model.md` and
   the architecture doc; the only "exactly once" phrases in code/docs
   refer to version increments per successful transaction, which the
   tests assert directly.

### §38 — clean-room

Clean-room verification from a pristine checkout (fresh clone of the
branch into a separate directory, venv from `requirements.txt`, full
35-module incident battery + pytest suites) is executed as the final
step of this phase; its recorded result is appended to PR #7 together
with the CI run ids, so this report only carries results that actually
ran.

### Deviations & known limitations (honest list)

- Session cannot create/use `dev/phase-8-control-plane-hardening-v1`
  (branch constraint above); work is on the session branch only.
- SQLite is the local test backend; PostgreSQL behavior is reasoned
  from identical predicate semantics and is exercised by the compose
  stack's smoke paths, not by a dedicated PG concurrency suite here
  (documented, not claimed as tested).
- In-process `threading` locks noted in the 8.0 persistence inventory
  remain secondary guards; durable claims/versions are the primary
  mechanism (documented limitation, unchanged).
- 8.0 implementation report section still pending (note at top).
