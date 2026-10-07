# Phase 8.4 — E2E Golden Path Report (Current Execution State)

## Executive result

```text
PARTIAL
```

- **Implemented + tested locally:** the mandatory integration-gap audit
  and the minimum contract-closure seams (§3–§6, §36) — commit
  `9014926`, verified by 24 new tests plus the full existing battery,
  exact-head CI green.
- **BLOCKED:** execution of the real staging golden path (§10–§53) —
  the assigned executor has **no container runtime** (details below).
  No golden-path stage has been run; every execution stage is
  **NOT VERIFIED** (§64 vocabulary). No stage is claimed PASS.

## Environment (observed, exact)

| Component | Observed |
| --- | --- |
| Executor host | KVM microVM, uid 1001, sudo/root available, 2 CPUs, 3.8 GiB RAM, 21 GiB disk |
| docker / dockerd | **NOT INSTALLED; all container registries unreachable** (`registry-1.docker.io`, `mirror.gcr.io`, `ghcr.io`, `quay.io`, `registry.k8s.io` → HTTP 000) and `apt` mirrors unreachable → **no installable runtime path** |
| kind / kubectl / terraform | NOT INSTALLED; `releases.hashicorp.com` unreachable |
| python | 3.11.2 (fresh venv, platform requirements from PyPI — PyPI reachable) |
| GitHub | reachable; owner token (gm-prog), repo `admin` |
| Implication | local compose/kind/terraform execution is physically impossible; the only viable execution venue is **GitHub Actions runners** (unrestricted network + docker), which this phase's harness/workflow must target |

Existing baseline facts used: `main = 7b30a56d…` untouched;
authoritative Phase 8.2 head `a0bf760`; Level 5 ref
`integration/phase-8.2-v1` = `a0bf760`; **PR #11 open, unmerged** (not
modified); PRs #8–#11 form the published stack (created by the
permitted 8.3.2 executor); session branch `arena/01a0cf63-…` advanced
only with documentation + these seam commits.

## Integration-gap audit (§2 — executable source is authoritative)

| Area | Finding | Evidence (source) |
| --- | --- | --- |
| Gateway JWT auth (401) | EXISTS | `api_gateway/core/auth.py` (`verify_token`, HS256, dev-fallback flagged) |
| Operator authorization (403) | EXISTS | `require_operator` + `OPERATOR_ROLES`; runs before downstream |
| Identity from JWT | EXISTS on approvals/executions | `control_plane.py` overwrites `requested_by`/`approved_by` with `user["sub"]` |
| Deployment dry-run/approve/execute/get routes | EXISTS | `control_plane.py` + `deployment_service/main.py` internal routes |
| Deployment state machine | EXISTS | `deployment_state.py`: …→AWAITING_APPROVAL→APPROVED→…→DEPLOYED (terminal) |
| Source verification / provenance / hashes | EXISTS | deployment engine + provenance record passed through collector |
| **Gateway incident GETs (list/by-id)** | **GAP → CLOSED** | added `GET /v1/incidents`, `GET /v1/incidents/{id}` (authenticated, read-only) |
| **Gateway RCA route** | **GAP → CLOSED** | added `POST /v1/incidents/{id}/rca` (operator) |
| **Gateway proposal-generation route** | **GAP → CLOSED** | added `POST /v1/incidents/{id}/proposal` (operator; only GET/approve/execute existed) |
| **Gateway deployment-evidence route** | **GAP → CLOSED** | added `POST /v1/incidents/{id}/deployment-evidence` (operator) |
| **Incident REST deployment-evidence** | **GAP → CLOSED** | handler+collector existed with no REST route; added fail-closed route (§4 contract) |
| **Agent `POST /api/internal/analyze-rca`** | **GAP → CLOSED** | agent service had only health+SSE; endpoint added with exact `RcaAgentClient` contract |
| **Deterministic RCA mode** | **GAP → CLOSED** | `E2E_DETERMINISTIC_RCA` adapter, 503 fail-closed otherwise (§6) |
| Monitoring ingestion + threshold breach | EXISTS | `POST /v1/gateway/dispatch/{service}` → `ThresholdValidator(danger=90.0)` → `ThreatThresholdExceededEvent` → `RedisStreamPublisher` |
| Incident event consumer | EXISTS (no HTTP health) | `incident_service/worker.py` + `redis_incident_consumer.py` — readiness must be process/stream-based, not HTTP (harness note) |
| Incident lifecycle + version CAS | EXISTS | aggregate guards; Phase 8.1 `UPDATE … WHERE id+version` in `postgres_incident_repo.py` |
| Proposal generate/approve/execute services | EXISTS | `proposal_generation/approval/execution_service.py` + lease coordination |
| Remediation orchestration + lease + reconciliation | EXISTS | `remediation_orchestration_service.py`, `proposal_execution_service.py` (`REMEDIATION_VALIDATION_PROFILE`) |
| Container validation sandbox | EXISTS | `container_validation_sandbox.py` (digest-pinned image via `REMEDIATION_SANDBOX_IMAGE`, `--pull never`, no host fallback) |
| **`e2e_fixture` validation profile** | **GAP → CLOSED** | added to `_DEFAULT_PROFILES` (code-owned fixed argv; env-selected only) |
| GitHub branch publish / PR / reconcile | EXISTS | `github_pr_client.py` + `remediation_workspace_push` |
| Compose topology (10 services) | EXISTS (no healthchecks) | `docker-compose.yml` — §11 readiness must be explicit in harness |
| E2E harness / compose override / workflow | ABSENT → next step | no `e2e/`, no `docker-compose.e2e.yml`, only `ci.yml` |

## Seam-closure evidence (executed)

Commit: **`9014926`** (`feat(e2e): close control-plane seams for staging golden path`).

| Test suite | Result |
| --- | --- |
| `api_gateway/tests/test_incident_control_plane_routes.py` | 8 passed + 18 subtests (401/403 matrix, no-downstream-on-403, faithful 404 relay, 502 unreachable, payload fidelity) |
| `tests/test_agent_rca_boundary.py` | 5 passed + 3 subtests (503 fail-closed outside E2E; deterministic result validated **through the incident service's own `parse_rca_result`**; cites only real pack ids; invalid packs 422; no secret material) |
| `tests/test_deployment_evidence_route.py` | 7 passed (404 incident without downstream call; collector 404/502 mapping; non-DEPLOYED & missing provenance → 422 not persisted; DEPLOYED persists + re-read; spoofed body field ignored) |
| `tests/test_e2e_validation_profile.py` | 4 passed (profile allowlisted, fixed argv, safe working dir, default profile unchanged, env-only selection) |
| Full regression (local, exact CI commands) | incident 35-module `OK (3 skipped)`; platform `272 passed + 112 subtests` (was 256+109); gateway `79 passed + 60 subtests` (was 71+42); backend `49 passed`; `compileall` OK; `git diff --check` clean |
| Exact-head CI (`9014926`) | push run `37432813784` + PR run `37432819275`: **success, 5/5 jobs each** (existing five-job workflow untouched — no `ci.yml` change) |

## Golden-path stages (§19–§53)

| Stage | Status |
| --- | --- |
| staging compose boot + readiness (§10–§12) | **BLOCKED** (no container runtime) |
| kind cluster + namespace isolation (§13–§14) | **BLOCKED** |
| Terraform zero-cloud plan/apply (§15) | **BLOCKED** |
| security negatives pre-flight (§17–§18) | partially covered in-process (gateway 401/403 matrix above); full external-host proof **NOT VERIFIED** |
| deployment dry-run→approve→execute→DEPLOYED (§19–§22) | **NOT VERIFIED** |
| monitoring breach → Redis → worker → incident (§24–§27) | **NOT VERIFIED** |
| evidence attach via external API (§28) | route verified in-process; external path **NOT VERIFIED** |
| RCA through agent boundary (§29–§30) | contract verified in-process (TestClient→agent app); networked chain **NOT VERIFIED** |
| proposal + independent hash + approval (§31–§34) | **NOT VERIFIED** externally (existing unit coverage remains green) |
| real execution → commit → remote push → PR (§35–§41) | **NOT VERIFIED** |
| duplicate/concurrent/stale/tampered/foreign/recovery (§42–§51) | **NOT VERIFIED** (existing in-repo unit suites still green) |
| DB cross-check (§53) | **NOT VERIFIED** |

## Hostile review questions (§71) — current answers

Q1–Q21, Q23: **NOT VERIFIED** (golden path has not run).
Q22 (anything touched `main`?): **NO** — `main` verified `7b30a56d…` unchanged after this commit's push.

## Security posture of the seams (verified)

- no anonymous control-plane access; mutating seams operator-gated
  before any downstream call;
- evidence fields never caller-supplied; validation occurs before
  persistence;
- deterministic RCA isolated behind explicit env; absence of provider
  fails closed (503); responses carry no secret material;
- `e2e_fixture` profile cannot receive request-defined commands.

## Known limitations

1. **No golden-path execution has occurred** — executor lacks any
   container runtime and registry access; the runnable venue is CI.
2. Harness (`e2e/`), `docker-compose.e2e.yml`, kind/terraform
   provisioning, disposable GitHub fixture, and
   `.github/workflows/e2e-golden-path.yml` (§57–§61) are **not yet
   built** → the DoD's execution items remain open.
3. ~~Exact `e2e_fixture` assertion value must be coordinated with the
   fixture file + generated patch when the harness lands~~ — closed by
   Phase 8.4.1: the profile asserts the exact patched value against
   `tests/fixtures/e2e_fixture_repo/` (see correction section below).
4. `REMEDIATION_SANDBOX_IMAGE` has no default (env-only) — the E2E
   environment must pin it (§12).
5. Unit/integration results above are **local + exact-head CI only** —
   never presented as staging E2E evidence (§69 distinction preserved).

## Test-type ledger (§69)

- unit/integration tests: executed locally, green (numbers above);
- exact-head CI: green at `9014926` (5/5 jobs, two runs);
- local/staging E2E: NOT RUN (blocked);
- real GitHub fixture: NOT CREATED;
- deterministic RCA: implemented + in-process verified (not networked);
- real external LLM: not used, not claimed;
- production deployment: never in scope.

## No exactly-once / provenance language

Any future E2E documentation for this platform must keep:
at-least-once attempts + deterministic idempotency + CAS + durable
lease + reconciliation + fail-closed (never "exactly once"). The
platform proves exact repository+SHA existence and artifact hashing —
**not** cryptographic source-to-artifact derivation; this report makes
no such claim (§67).

## Phase 8.4.1 correction — deterministic RCA → proposal closure (2026-10-06)

The 8.4 report's known limitation is now closed at unit/integration
level: the deterministic adapter returned no `remediation_draft`, so
`ProposalGenerationService` correctly blocked with `BLOCKED_NO_DRAFT`
and the deterministic path could never reach an executable proposal.
Implementation commit `32a262f`.

### Proven after this task

- deterministic RCA validates the real synthetic breach semantics
  (fail-closed `validate_e2e_signal`: pack structure, timeline ids,
  exactly one `checkout-service`/`cpu_percent` signal, numeric
  observed value + configured danger threshold read from the pack,
  `observed > threshold`) — wrong service, wrong metric, missing
  numbers, missing signals, ambiguity and foreign ids all return 422;
- deterministic RCA emits the controlled, code-owned remediation
  draft (target `src/service_config.py`, exact single-file unified
  diff `SERVICE_NAME = "checkout-service"` →
  `"checkout-service-remediated"`, fixed validation plan, `LOW`);
  the request can never supply repository/SHA/branch/command;
- `parse_rca_result()` accepts the result — proven at parser level
  (schema, evidence refs ⊆ incident evidence, draft validation), and
  rejects foreign citation sets;
- canonical `ProposalGenerationService.generate()` produces a
  `PROPOSED`, verified proposal with repository and source SHA taken
  exclusively from authoritative deployment evidence, deterministic
  canonical hash (stable across equivalent evidence; sensitive to
  patch/target/repository/SHA/risk/validation-plan/evidence-refs
  mutations), incident reaching `RemediationProposed`;
- fixture validation asserts the exact expected patched value
  (AST-exact; initial value, substring lookalike and missing file all
  fail) without Docker, plus a cross-service drift guard;
- production RCA remains fail-closed (`E2E_DETERMINISTIC_RCA`
  absent/false → 503); a valid RCA without a draft still blocks with
  `BLOCKED_NO_DRAFT`; no secret material in deterministic outputs;
- no production deployment or GitHub fixture was executed by this
  task.

Local battery (exact CI scopes): platform `300 passed + 124
subtests`; incident 35-module `OK (559 tests, 3 skipped)`; gateway
`79 passed + 60 subtests`; backend `49 passed`; `compileall` OK;
`git diff --check` clean.

### Still unproven (unchanged from §Stages)

real container staging boot; kind cluster; real Terraform execution;
real deployment → DEPLOYED; real monitoring → Redis → worker chain;
real external API golden path; real sandbox execution in CI; real
Git commit; real GitHub branch; real GitHub PR; external duplicate
execution; external concurrency; external crash/recovery; database
cross-check under full E2E.

Phase 8.4 is NOT complete and no staging success is claimed.

## Next steps (in order)

> **Superseded in part by Phase 8.4.2** — the harness, compose
> override, kind/terraform fixtures, workflow and hostile-path driver
> now exist (see `docs/PHASE-8.4.2-E2E-GOLDEN-PATH-IMPLEMENTATION-REPORT.md`);
> what remains is the protected-environment + fixture-repository
> execution procedure recorded there.

1. Build the §57 harness + `docker-compose.e2e.yml` (pinned images) with
   explicit readiness probes;
2. Add `.github/workflows/e2e-golden-path.yml` (`workflow_dispatch`,
   protected `e2e-staging` environment, no `pull_request_target`,
   no `cancel-in-progress`);
3. Create the disposable fixture repository + least-privilege credential
   (never the production repo, never committed);
4. Execute on a CI runner (kind + terraform + compose), collect §55
   artifacts, fill the §68/§70 tables with observed results;
5. Only then re-answer §71 and update this report's executive result.
