# CHANGELOG

## 2026-10-02 — Phase 6.5.1: runtime release identity carrier for Prometheus attribution

- **Identity provider** (`backend/app/release_identity.py`) —
  `DEVOPS_DEPLOYMENT_ID` (exact Phase 6.4 deployment run id, 1–128
  chars, no control characters, preserved verbatim) + `DEVOPS_SOURCE_SHA`
  (exact lowercase 40-hex: uppercase/whitespace/prefixed/short rejected)
  validated fail-closed at startup; deterministic, unit-testable,
  values never echoed. Root compose passes both through to the api
  service as empty-default env (no hard-coded identity, no secrets).
- **Low-volume carrier metric** — exactly one
  `devops_release_identity_info{deployment_id,source_sha} 1` series on
  valid identity; invalid/missing identity exposes **no** series (never
  fabricated) so Phase 6.5 stays INCONCLUSIVE. Release labels are NOT
  added to `devops_api_requests_total` (method/path dimensions
  unchanged) — identity stays on one series per process instead of
  multiplying time series.
- **PromQL join** — both fixed templates now inherit identity via
  `* on(job, instance) group_left(deployment_id, source_sha)
  devops_release_identity_info` before the existing `sum`/`avg`
  aggregation (join keys = scrape-target labels from
  `monitoring/prometheus.yml`: job `devops-api-gateway`, target
  `api:8000`). Template names, query budget (1/SLI), attribution
  rules, decisions, byte/sample bounds, timeout and instant-query
  contract unchanged; no arbitrary PromQL, no new dependencies.
- Tests: new `backend/tests/test_release_identity.py` (validation
  matrix, single-series/value-1 exposition, no-series on invalid,
  request-counter dimensions intact, no release labels on any app
  metric) + template join/by-clause proofs and joined-output-shape
  attribution in `tests/test_live_release_verification.py`.

## 2026-10-02 — Phase 6.5 corrective: bound Prometheus range-query response body

- `PrometheusScraperClient` range path now enforces a fixed
  `MAX_RESPONSE_BYTES = 4 MiB` **before** JSON parsing, alongside the
  existing independent `MAX_RESPONSE_SAMPLES = 10 000` logical limit:
  an oversized declared `Content-Length` fails before any body read;
  missing/chunked length is read in bounded 64 KiB increments that stop
  at limit + 1 probe byte (no unbounded `response.read()` anywhere on
  the range path); untrustworthy `Content-Length` fails closed with the
  typed malformed-response error and messages never echo bodies or
  headers. Sample-cap, timeout, non-200, window/template/attribution/
  decision semantics and the instant-query contract are unchanged.

## 2026-10-02 — Phase 6.5: change-aware live release verification

- **Combined read-only endpoint** —
  `GET /changes/{deployment_run_id}/live-health?start&end[&baseline_deployment_run_id]`
  (incident service; forwarded as `GET /v1/changes/…/live-health` by the
  API gateway behind JWT `verify_token` + rate limit, any authenticated
  user). Response = `{durable_assessment, live_assessment}`: the
  unchanged Phase 6.4 durable result plus the Phase 6.5 live telemetry
  result — 6.4 decision semantics consumed verbatim, never altered.
- **Bounded Prometheus range query** — `query_range_metric()` added to
  the existing `PrometheusScraperClient` (same endpoint configuration;
  instant-query behavior preserved): fixed 5 s timeout, ≤31-day window,
  ≤500 points/query, ≤10 000 samples/response, predefined templates
  only (`request_rate`, `cpu_saturation` — no arbitrary PromQL anywhere
  in the path), fail-closed typed errors on timeout/HTTP/malformed/
  unsupported/overflow, deterministic typed models
  (`RangeQueryResult`/`RangeSeries`/`RangeSample`). Exactly one query
  per SLI per assessment (no N+1).
- **Exact release attribution** — a series counts only when label
  `deployment_id` equals the Phase 6.4 deployment run id or label
  `source_sha` equals the exact 40-hex source SHA; `service_version` is
  not authoritative (no durable version exists to match); timestamps
  never attribute. Templates group `by (job, deployment_id,
  source_sha)` — no new instrumentation labels added.
- **Deterministic SLI rules** — fixed precedence
  FAILED > DEGRADED > INCONCLUSIVE > HEALTHY with structured reason
  tokens: `cpu_saturation_critical` (≥0.90 cores → FAILED),
  `cpu_saturation_warning` (≥0.70 → DEGRADED),
  `request_rate_dropped_vs_baseline` (<50 % of an explicit, attributable
  baseline → DEGRADED); INCONCLUSIVE for unavailable/malformed/
  unsupported telemetry, <3 attributable samples, unattributable series,
  or an unresolvable requested baseline; HEALTHY only with all signals
  attributable, populated, and within policy. Missing ≠ zero; malformed
  ≠ signal; time proximity ≠ correlation. Error-rate/latency SLIs
  intentionally omitted (no backing telemetry in-repo).
- **Fail-closed HTTP map** — window → 422 (Phase 6.3 validator),
  unknown run → 404, every telemetry failure → 200 with
  `INCONCLUSIVE` + fixed six-reason data-quality block. Read-only: no
  mutation path, no schema, no CI-workflow change.
- Tests (existing modules + one new platform file): bounded query
  bounds/timeout/malformed/unsupported/sample-cap, instant-query
  preservation, exact-attribution matrix (wrong SHA/run, timestamp-only
  overlap), all four decisions + reason order, baseline
  valid/missing/unattributable, exact `[start,end)` sample boundaries,
  fixed 2-query budget with baseline + noise series, query-before-
  nothing on 404/422, combined read model, controller/E2E/gateway
  auth+forward+relay matrix.

## 2026-09-28 — Phase 6.4: change intelligence & release verification foundation

- **One typed read-only endpoint** —
  `GET /changes/{deployment_run_id}/health?start&end` (incident service),
  forwarded as `GET /v1/changes/{deployment_run_id}/health` by the API
  gateway behind the existing JWT `verify_token` auth + rate limit (any
  authenticated user; no patch content). Application service owns
  correlation + the deterministic rule evaluator; repository owns reads;
  no SQL in handlers; no mutation path exists on this surface.
- **Change ↔ incident correlation on durable identifiers only:**
  strong basis = exact `deployment_run_id` in incident
  `kind="deployment_run"` evidence; supporting basis = exact
  `repository_name` + exact deployed `head_sha` matching the
  authoritative record (latest exact-id record by `(observed_at,
  evidence_id)` — the remediation-binding winner rule). Timestamp
  proximity never links; correlation is reported as association, not
  causation. Reuses collector-captured fields and the Stage-5
  `_provenance_satisfies_record` identity guarantee — no second
  deployment database, no new schema.
- **Release health decisions** — exactly `HEALTHY` / `DEGRADED` /
  `FAILED` / `INCONCLUSIVE`, from explicit typed rules with fixed
  precedence and fixed structured reason tokens (no ML/LLM/probabilistic
  scoring). FAILED = authoritative failure fields (terminal-failed
  state, health `FAIL`, rollback `FAIL`); DEGRADED = deterioration
  (rollback-pending/rolled-back state, unresolved linked incidents using
  the existing `Fixed`/`Resolved` terminal vocabulary, linked
  `EXECUTION_FAILED` remediation); INCONCLUSIVE = required evidence
  missing/untrustworthy (identity, state, health, provenance gaps) —
  never forced to HEALTHY; malformed evidence never becomes FAILED
  without an independent authoritative field. HEALTHY requires the full
  green set (state `DEPLOYED`, health `PASS`, valid provenance,
  complete identity, no unresolved/failed linked work).
- **Bounded reads & window contract** — reuses the Phase 6.3 window
  read (two statements total, no N+1: no per-incident claim queries, no
  per-evidence loops) and the Phase 6.3 window validator verbatim (UTC
  half-open `[start, end)`, ≤31 days, 422 invalid/oversized, 404
  unknown-in-window, byte-identical determinism). Data-quality block
  mirrors Phase 6.3 (fixed exclusion vocabulary always fully present).
- Tests (existing modules only — no CI workflow change): correlation
  basis/anti-patterns (wrong SHA/repo, timestamp proximity),
  the four decisions + reason-order determinism, DQ vocabulary pin,
  read-only/mutation guards, no-patch-material assertion, window/bounds
  ([start,end) exact-boundary + cohort 404), real-adapter query-budget
  regression, HTTP E2E (422/404/200 + byte determinism), gateway
  auth/forward/relay matrix.

## 2026-09-28 — Phase 6.3 corrective pass: analytics read path, metadata honesty, cohort contract

- **No N+1 on the analytics window read:** `list_incidents_in_window`
  no longer applies the per-incident claim overlay (analytics does not
  need live execution-lease/claim state) — exactly two statements
  (incident window query + one bulk evidence query) regardless of cohort
  size, proven by a query-budget regression test. Normal reads
  (`get_incident_by_id`/`get_active_incidents`) keep their overlay and
  all claim/CAS/lease semantics are untouched.
- **Malformed execution metadata can no longer fabricate outcomes:**
  validation is classified only by a well-formed boolean
  `validation.completed.passed` (True → success, False + finished
  FAILED attempt → validation failure); non-mapping metadata, a missing
  `passed` key, or a non-boolean value is recorded as the new data-quality
  reason `execution:validation_metadata_malformed` and classified as NOT
  failed (partition preserved). Publication/PR phases remain pure
  durable-stage-membership checks (metadata never read there).
- **Incident-cohort window semantics locked:** documented in the service
  docstring + README and pinned by tests — the window selects incidents
  by `incident.created_at` (half-open UTC `[start, end)`); child facts
  of selected incidents are analyzed even when their own timestamps fall
  outside the window, and in-window child events never pull an
  out-of-window incident into the cohort.
- **Dead Phase 6.3 leftovers removed:** unused `EXECUTION_STAGES` import;
  unreachable DQ vocabulary `timing_approval_to_completion:evidence_payload_malformed`;
  stale README claim that validation "executes in-process on the
  incident-service host" (contradicts the Phase 6.2.2 container sandbox).

## 2026-09-28 — Phase 6.3: evidence-driven operational analytics & remediation intelligence

- **One read-only summary endpoint** — `GET /incidents/analytics/summary`
  (incident service) forwarded as `GET /v1/analytics/summary` by the
  API gateway behind the existing JWT `verify_token` auth + rate limit
  (any authenticated user; aggregates expose no patch content).
  Application service owns window validation + aggregation; handlers
  contain no SQL and no business rules.
- **Bounded, deterministic windows:** half-open UTC `[start, end)` of at
  most 31 days (service-validated → 422), explicit sorts everywhere,
  zero-filled UTC day buckets, integer-second timing with nearest-rank
  p50/p95 (sample and exclusion counts always visible), one pure
  aggregation (no clock reads), byte-identical responses for identical
  durable records.
- **Metrics backed ONLY by durable authoritative records:** incident
  volume (total/by UTC day/by severity/by status), RCA coverage
  (evidence presence — never free-text guessing), proposal outcomes
  (durable status + `approved_at`), pipeline phase partitions
  (validation/commit/publication/PR from proposal status + latest
  execution-evidence `stages` notify progression — every proposal lands
  in exactly one bucket per phase), failures by stage (verbatim
  `last_failure_stage` group-by), and the two timing intervals whose
  BOTH timestamps are durable (`generated_at→approved_at`,
  `approved_at→` execution completion).
- **No fabrication:** every response carries a fixed data-quality
  exclusion block (missing timestamps, negative durations, incomplete
  executions, malformed/unmatched evidence — counters always present,
  zero unless stated) plus an explicit UNSUPPORTED manifest with
  BECAUSE/WOULD REQUIRE reasons: counts by service/component, RCA
  category histogram, rejected/expired proposals, recovery, recurrence,
  and the five pipeline timing intervals with no durable timestamps.
- **New repository window read** (port + SQLAlchemy adapter,
  `list_incidents_in_window`) — parameterized, `created_at` in
  `[start, end)`, deterministic `ORDER BY created_at, id`, single bulk
  evidence query, claim overlay applied like every other read. No
  schema change, no new table, no new dependency; Phase 6.2.1 lease/CAS
  and 6.2.2 sandbox semantics untouched.
- §17 self-observability: one bounded-label counter
  (`analytics_summary_requests_total{outcome}`) through the existing
  shared metrics facade — metrics never break queries and Prometheus is
  never a data source for analytics.
- Tests: service unit/data-quality/determinism + E2E fixture through
  the REAL repository adapter (SQLite), controller contract (422 map),
  HTTP E2E (FastAPI param validation, route non-shadowing, byte
  determinism), gateway auth/forward/relay matrix (2 new modules
  registered in CI → 30).

## 2026-09-28 — Phase 6.2.2 corrective pass: read-only validation workspace & target integrity

- **The real remediation Git workspace is now bound READ-ONLY into the
  validation sandbox** (`<workspace>:/workspace:ro`; the only writable
  area remains the bounded tmpfs `/tmp`). The untrusted validation
  workload can observe the working tree and `.git` (inside the same
  RO mount) but can never write the host repository, the approved
  target, or Git metadata through it. No alternate RW host-repository
  mount exists (exactly one bind, always `:ro`).
- **Before/after integrity around every sandboxed step:** the host
  snapshots the approved target's SHA-256, HEAD, the target's staged
  and working-tree diff state, and `.git/HEAD`/`.git/index`/`.git/config`
  digests immediately before and after each step and requires exact
  equality — a zero exit code alone never authorizes a changed
  workspace. The comparison is before-sandbox == after-sandbox (the
  target already carries the approved remediation patch), and all
  validation-time Git reads use `--no-optional-locks` so validation is
  observationally side-effect-free on `.git/index`.
- Focused regressions: `:ro` plan assertions, no-writable-`.git` mount
  checks, a non-Docker mutating-sandbox test
  (`ValidationWorkspaceMutationError` fail-closed), unchanged-approved-
  target acceptance, and real-container probes that attempt (and have
  denied) target rewrites and harmless `.git/HEAD|index|config` writes
  with byte-identical host state afterwards.
- Honest scope: this narrows the claim to "the validation workload gets
  a read-only view of the remediation workspace and cannot write the
  host repository or Git metadata through the mount" — the host still
  performs controlled Git patch/commit/publish operations outside the
  sandbox. Not "escape-proof", not "production-safe", not exactly-once.
  Phase 6.2.1A/B/C lease/CAS/heartbeat/reconciliation/PR-identity
  semantics unchanged.

## 2026-09-28 — Phase 6.2.2: hardened remediation execution sandbox

- **Validation workloads now execute ONLY inside a dedicated container
  sandbox** (`ValidationSandboxPort` → `ContainerValidationSandbox`).
  The remediation runner requires an explicitly injected sandbox; there
  is no default and NO host-execution fallback — sandbox runtime,
  image, configuration, timeout or result failures raise typed
  `ValidationSandbox*` errors and the workload never runs on the host.
  The legacy in-process executor survives only as
  `LocalProcessValidationExecutor`, an explicit unit-test/dev seam that
  production wiring (`controllers.get_remediation_orchestrator`) cannot
  reach.
- **Isolation configuration (generated per step, unit-tested):**
  digest-pinned image with `--pull never` (floating tags rejected),
  `--network none` (the only network mode the policy accepts), non-root
  `--user`, `--read-only` rootfs + tmpfs `/tmp`, `--cap-drop ALL`,
  `no-new-privileges`, seccomp (runtime default; configured profiles
  validated, `unconfined` forbidden), `--pids-limit`/`--memory`/`--cpus`
  bounds, wall-clock timeout with grace, unique per-attempt container
  name, exactly ONE bind mount (the ephemeral workspace at
  `/workspace`), `--rm` + unconditional best-effort `docker rm -f`
  cleanup on every exit path.
- **Credential isolation:** sandbox environment is built exclusively
  from a constant allowlist (`SANDBOX_ENV_ALLOWLIST`); host variables —
  `GITHUB_OAUTH_TOKEN`, `JWT_SECRET`, database/Redis URLs, cloud keys,
  SSH config — are never forwarded via env, mounts or defaults.
- **Untrusted repository content** (patched files, test/build scripts,
  filenames) can only influence its own test inputs: argv, executable,
  limits, mounts, network mode and credentials remain host policy;
  hostile filenames fail the pre-execution workspace-state check and
  never reach the sandbox.
- Lease semantics unchanged: `before_side_effect` still guards
  `validation.run` before any sandbox creation, heartbeats continue
  during execution, and stage/finish writes remain owner/expiry/CAS
  gated. Phase 6.2.1A/B/C reconciliation semantics untouched.
- Honest limits: one real-container integration test runs only where a
  docker runtime exists (GitHub-hosted runners provide one; it skips
  otherwise) — without a runtime, the proof surface is configuration
  generation, not kernel enforcement. Not "production-safe",
  "escape-proof" or exactly-once. Concurrent PostgreSQL behavior
  unchanged from previous phases.

## 2026-09-28 — Phase 6.2.1C: finish CAS atomicity & post-create PR uniqueness (corrective hardening)

- **Finish transaction atomicity.** `finish_execution_lease()` now raises
  the existing `_CoordinationRace` when its final claim CAS affects zero
  rows, instead of returning normally. The proposal/status/stage/commit/
  branch/PR-URL/failure-field mutations staged earlier in the same
  transaction are thereby rolled back wholesale: a stale worker whose
  lease was replaced can never commit terminal proposal state or attach
  evidence through that path. Callers keep the existing typed failure
  behavior (`ExecutionLeaseUnavailable`, fail closed). Transactional
  stale-writer isolation only — not exactly-once semantics.
- **Post-create pull request uniqueness.** `_verify_created_pr_identity()`
  now requires the deterministic head/base pair to resolve to exactly
  ONE discovered PR (`len(matches) == 1`) before verifying that sole PR's
  exact URL, repository, head branch, executed head SHA, allowed base,
  open/unmerged state — and that it is still a draft (this phase stops at
  a draft PR). A duplicate PR discovered next to the created URL is a
  conflict; no second create, no retarget, no force-push. Existing
  discovery-before-create reuse rules are unchanged.
- Honest limit: concurrency exercised on SQLite through the portable
  SQLAlchemy path; PostgreSQL concurrent-writer behavior remains a known
  CI limitation. Not "production-safe" by assertion.

## 2026-09-27 — Phase 6.2.1B: lease expiry enforcement & pre-side-effect authorization (corrective hardening)

- **Lease expiry is now authoritative for every durable write.** `renew_execution_lease`,
  `persist_execution_progress` and `finish_execution_lease` require
  `state == LEASED` **and** `lease_owner == caller` **and** a non-null
  `lease_expires_at > now`, enforced in SQL inside the read check and the
  final UPDATE CAS (single atomic statement, app-side filtering only as
  defence in depth). An expired worker — even one whose `lease_owner` row
  still matches — can no longer renew, persist progress, write evidence,
  release the lease, or persist a terminal state after another worker has
  re-claimed it.
- **Pre-side-effect authorization guard.** A single reusable check,
  `ProposalExecutionService.assert_execution_lease_live(incident_id,
  proposal_id)`, verifies (1) this attempt's heartbeat has not detected
  ownership loss, (2) the durable claim row still exists, (3) `state ==
  LEASED`, (4) `lease_owner` is this worker, (5) `lease_expires_at > now`.
  Store/network uncertainty raises the same typed guard error (fail
  closed). The orchestration layer receives it as an injected
  `before_side_effect(name)` callback — it never learns database details —
  and the guard runs immediately before **every** remote side effect:
  workspace prepare, patch apply, validation run, commit create,
  publish, remote branch create, pull-request discovery (the control-plane
  read that decides whether to mutate) and PR create, plus every resume
  path (`remote.inspect` before any resume remote read). If the guard
  refuses, the side-effecting function is never invoked; the failure
  flows through the existing classification and owner-gated persistence.
  A successfully guarded boundary means only that the durable control
  plane reports live ownership at that instant — external operations are
  **not** atomic with the database lease; heartbeats during the
  operation, owner-gated post-stage CAS, reconciliation and fail-closed
  sequencing remain as defence in depth. Exactly-once external execution
  is explicitly not claimed.
- **Active incident list projection fixed.** `get_active_incidents()`
  now applies the same all-claims → proposal-keyed overlay used by
  `get_incident_by_id()`, so `GET /incidents` reports each proposal's own
  durable stage/attempt/owner/commit instead of inheriting whichever
  claim row was read first (or nothing).
- **Post-create PR identity verification.** After `create_pull_request`
  succeeds, the orchestrator performs a bounded re-discovery and requires
  the returned pull request to prove exact identity: same repository as
  the proposal, deterministic head branch, `head_sha == executed commit`,
  allowed `base_ref`, open and unmerged, exact URL match (body hash only
  as corroboration, never as identity). Mismatch or malformed discovery
  output raises a typed conflict/reconciliation failure and the operation
  fails closed — no second create, no retarget, no force-push, no
  merge — while the pre-existing discovery-before-create reuse policy
  (zero second creates on lost responses) is preserved.
- Honest limits: PostgreSQL concurrency for the expiry CAS is exercised
  in tests through the portable SQLAlchemy statement path but concurrent
  multi-writer races are only covered on SQLite; this is not
  "production-safe" by assertion. No schema change (no migration needed).

## 2026-09-27 — Phase 6.2.1A: lease liveness & remote identity integrity (corrective hardening)

Closes three review gaps on the completed 6.2.1 implementation; no
architecture change, pipeline unchanged (approved proposal → controlled
remediation → draft PR).

* **Active lease liveness** — new owner-CAS renewal primitive
  `renew_execution_lease` (stage-neutral, exact claim, never resurrects
  or extends foreign leases; no schema change) plus a worker-owned
  heartbeat thread active for exactly one execution attempt. Interval =
  `REMEDIATION_EXECUTION_HEARTBEAT_SECONDS` or derived `lease/3`
  (always positive and `< lease/2`, fail-fast validation). Lease loss
  or claim-store uncertainty is detected immediately and the next
  side-effecting stage is refused (stage guard); persistence/finish
  paths convert store unavailability to typed fail-closed errors. A
  worker that lost its lease cannot clobber the new owner's state; an
  in-flight external operation is never "cancelled" — only the next
  stage is blocked, recovery runs through the existing reconciliation
  path. Heartbeats are stopped and joined on every exit path (no thread
  leaks).
* **Exact PR identity** — `ExistingPullRequest` exposes `head_sha` +
  `head_repository`; reuse now requires exact repository + head branch +
  head commit SHA + allowed base + open/unmerged, with the proposal
  hash in the body remaining corroboration only. Wrong head SHA, wrong
  or absent head repository, wrong base, merged/closed, multiple
  matches, or body-only agreement → `ExistingPullRequestConflict`,
  fail closed (no second PR / overwrite / force-push / retarget).
  Malformed head identity in API payloads → typed discovery failure.
* **Multi-proposal claim projection** — incident reload fetches ALL
  claim rows per incident and maps them by `proposal_id`; proposals with
  no claim keep their JSON view; independent stage/attempt/lease/
  commit/branch/PR per proposal proven on real SQLite (active, completed,
  failed and claim-less proposals side by side). Added read helper
  `get_execution_claims_for_incident`.
* **Tests:** new `test_proposal_lease_liveness` (13 — interval policy
  fail-fast, renewal CAS semantics, long-operation/long-validation
  renewal on real store, owner-loss stops next stage + cannot finish,
  store-outage fails closed, no heartbeat-thread leaks); multi-proposal
  projection (1); client exact-identity + malformed-head tests (+3);
  orchestration wrong-SHA/wrong-repo/wrong-base/body-only-never-reuses
  tests (+6); §29-D recovery E2E — PR created remotely with lost
  response, worker B reuses the exact PR with zero second creates (+1).
  Full battery: backend 38, platform 137+78 subtests, gateway 34+36
  subtests, incident **27 modules Ran 255 OK**.
* **Honest limitations:** PostgreSQL CAS still not exercised in CI
  (SQLite real-persistence only); in-flight operations cannot be
  cancelled after lease loss; no hardened sandbox (Phase 6.2.2); no
  exactly-once across DB+Git+GitHub.

## 2026-09-27 — Phase 6.2.1: durable execution coordination & remote reconciliation

Hardens the Phase 6.2 executor (same architecture, no new stack): one
logical proposal execution now converges to one logical remediation
result under duplicate, interrupted and ambiguous requests.

* **Durable execution lease** — new `devops_execution_claims` table
  (same database, explicit schema, reload round-trip tested) holding
  `execution_id, attempt, lease_owner, lease_acquired_at,
  lease_expires_at, current_stage, state, commit/branch/pr mirrors`.
  Atomic claim guarantees at most one live lease per
  `(incident_id, proposal_id, proposal_hash)` **across independent
  service instances** (verified with two adapters over real SQLite,
  including a threaded CAS race). TTL from
  `REMEDIATION_EXECUTION_LEASE_SECONDS` (default 600.0, positive,
  fail-fast, tz-aware); fresh leases can never be stolen; progress
  writes renew expiry; `attempt` increments only on a real ownership
  claim. Lease owner is process-derived — the execute API still accepts
  only `{proposal_id, proposal_hash}` (+ authenticated operator),
  never owner/repository/target.
* **Bounded durable stage vocabulary** — `CLAIMED → WORKSPACE_CREATED →
  PATCH_APPLIED → VALIDATION_STARTED → VALIDATION_PASSED → COMMIT_CREATED
  → REMOTE_PUBLISHED → REMOTE_VERIFIED → PR_DISCOVERY → PR_CREATED →
  COMPLETED|FAILED`, each transition a short owner-gated transaction
  (never held across external ops). Losing the lease mid-run aborts the
  orchestrator (`RemediationStageGuardError`) without clobbering the
  new owner's state.
* **Crash recovery reconciles reality first** — expired lease reclaim
  re-runs integrity/freshness/patch/target gates, then inspects durable
  cursor + `ls-remote` SHA before choosing RESUME (remote == persisted
  commit → skip workspace, converge PR) or a deterministic FULL
  restart; missing/vanished or mismatched remotes fail closed with
  durable `RECONCILIATION_CONFLICT` evidence — never retarget, never
  force-push.
* **Mandatory PR reconciliation** — new
  `GitHubPRClient.find_existing_pull_request(s)` (auth, slug/base
  validation, bounded timeouts, distinct 401/403/404/429/5xx typed
  outcomes, no token leakage, typed `ExistingPullRequest` results) runs
  before every create: 0 → create, 1 open exact-identity match → reuse,
  merged/closed/multiple/mismatched-corroboration →
  `ExistingPullRequestConflict` fail closed. head/base/repository are
  the identity; PR body metadata is corroboration only — remote state
  is never authorization. Branch publication reconciles the same way
  (absent → push, equal → idempotent, unequal → conflict).
* **Failure/HTTP map:** new typed `ExecutionLeaseUnavailable`,
  `RemoteBranchConflict`, `ExistingPullRequestConflict` → 409;
  `RemoteReconciliationFailed` → 502 (`ExecutionLeaseExpired`,
  `ExecutionRecoveryConflict` remain reserved vocabulary). Active
  lease → 409 (no parallel execution); retry-after-success returns the
  existing result without incrementing attempts; unrecoverable
  conflicts stay `EXECUTION_FAILED` until operator action.
* **Observability:** `remediation.lease.acquired|rejected|expired`,
  `recovery.started|reconciled`, `remote.branch.reconciled`,
  `pr.discovery|reconciled|created`, `execution.completed|failed` —
  observer failures never change semantics. Per-attempt evidence
  (`exec-{id}-a{attempt}`) carries stage, status, repo, SHAs, lease
  owner and redacted reason; conflict evidence
  (`exec-{id}-recon-a{n}`) persists pre-lease reconciliation failures.
* **Tests (all green locally):** durable lease coordination (19 —
  two-instance claims, expiry reclaim, owner-gated finish, thread CAS
  race, stage guard, vocabulary, fail-closed store), service recovery
  (11 — crash/RESUME/FULL/vanished/wrong-SHA, stale/tampered/drift
  gates, lease theft mid-run), discovery client (21 — typed status
  matrix, filters, token-free messages), orchestration reconciliation
  (16 — reuse/merged/multiple/body-hash, resume re-inspect), §44
  recovery E2E with bare git + deterministic fake GitHub HTTP
  (worker A push → crash → worker B converges to exactly 1 commit /
  1 branch / 1 PR; PR-response timeout retry; wrong-SHA fail-closed;
  merged-PR no-second-PR), plus the full proposal battery —
  156 passed / 29 subtests. CI incident job: 26 modules (+2).
* **Honest limitations:** TTL lease ≠ distributed consensus (no
  exactly-once claim across DB+Git+GitHub — at-least-once +
  deterministic idempotency + fail-closed reconciliation only);
  PostgreSQL DDL mirrors SQLite but is not exercised in CI; hostile
  remote history beyond branch SHA/PR identity fails closed to an
  operator; workspace+subprocess still not a hardened sandbox.

## 2026-09-27 — Phase 6.2: controlled remediation execution (proposal → approval → validated patch → draft PR)

Completes the bounded vertical slice: an evidence-grounded, persisted
proposal can now be approved by an authenticated operator and executed
by deterministic code up to a **draft GitHub PR** — and nothing else.
No merge, no approve of the PR itself, no deploy/canary/rollback, no
authorization escalation, no multi-agent or model-supplied commands.

* **Approval (`POST /incidents/{id}/proposal/approve`).** Deterministic
  policy only: proposal exists, status approvable (`BLOCKED` never),
  canonical hash reproducible from persisted state and equal to both the
  stored and caller-claimed hash, risk class within the bounded
  `LOW`/`MEDIUM` set, generation → approval inside
  `REMEDIATION_PROPOSAL_TTL_SECONDS` (default 86400), and the
  authoritative deployment target still matching the proposal's trusted
  repository/SHA. `approved_by` is stamped from the verified JWT subject
  at the gateway (`/v1/incidents/{id}/proposal/approve`, operator role);
  AI confidence is never consulted for authorization. Approval persists
  `APPROVED` + `approved_by/approved_at/approval_hash` on the existing
  aggregate (idempotent for the same hash).
* **Execution (`POST /incidents/{id}/proposal/execute`, operator).**
  Pre-flight re-verifies integrity, approval freshness (TTL), patch
  policy and the authoritative target (mismatch → abort, never
  retarget), persists `EXECUTING` with a deterministic
  `uuid5(proposal_id:proposal_hash)` execution id, then runs the
  existing orchestration stack unchanged (SHA-pinned isolated workspace →
  bounded `git apply --check` → fixed validation profile → deterministic
  commit with parent == pinned SHA → push `automation/remediation/*` →
  remote SHA verification → **draft** PR). Success persists
  `PR_CREATED` + commit/branch/PR identity and attaches machine-readable
  `remediation_execution` evidence (`exec-{id}-a{attempt}`); failure
  persists `EXECUTION_FAILED` with stage + redacted reason and allows
  retry. Repeat execution reconciles the stored PR (same identity, no
  second push).
* **Lifecycle fields (additive):** `approved_by`, `approved_at`,
  `approval_hash`, `execution_id`, `executed_at`, `commit_sha`,
  `branch_name`, `execution_attempts`, `last_failure_stage`,
  `last_failure_reason`, plus statuses `APPROVED/EXECUTING/PR_CREATED/
  EXECUTION_FAILED` — restored on reload through the existing
  postgres/sqlite adapter; no schema/table changes.
* **Typed failures + HTTP map:** 404 not found / 422 integrity, patch
  policy, validation-failed / 409 not-approved, executing, stale /
  403 approval-policy, target-revalidation / 502 GitHub-remote failure.
* **Heredity fixes found while wiring the chain:** deterministic
  committer identity for remediation commits (a cloned workspace has no
  `user.name/user.email`; fixed non-impersonating
  `devops-ai-remediation@noreply.invalid`, env-overridable) and a
  composition-time remote-URL seam on the workspace service (production
  default still the fixed GitHub URL; tests inject a local bare origin).
* **Observability:** structured `remediation.*` logs for approval,
  target revalidation, execution start/stage/complete/fail/reconcile.
* **Tests:** approval policy matrix, execution gates + failure matrix
  (unapproved, wrong hash, tampered patch/path, deployment drift, stale,
  validation failure, GitHub failure, patch rejection, redaction, retry,
  duplicate reconcile, concurrency invariant, injection-as-data),
  controller mapping, gateway operator routes, and a real-git E2E
  (persisted proposal → approval → execution → bare-origin push → draft
  PR). CI incident job: 24 modules.
* **Honest limitations:** process-local locks (not distributed),
  workspace+subprocess ≠ hardened sandbox, crashed `EXECUTING` needs
  manual recovery, non-fast-forward push retries fail closed.

## 2026-09-27 — Phase 6.1 live vertical slice: monitoring runtime wiring

Closes the last runtime gap of the monitoring → proposal chain (proposal
remains proposal-only; nothing executes).

* **Monitoring composition root** — `monitoring_service` now composes the
  real producer at runtime: `application/dependencies.build_threshold_monitor()`
  (env `MONITORING_DANGER_LIMIT`, fail-fast config) → `RedisStreamPublisher`
  (`EVENT_BUS_REDIS_URL` / `EVENT_BUS_STREAM`) → existing
  `ThresholdValidator`; the entrypoint only wires routers/delegates.
* **Runtime input** — `POST /api/internal` on the monitoring app (the
  gateway `dispatch/monitoring` target, envelope
  `{"payload": <observation>, "forwarded_by": <jwt sub>}`) validates
  observations (bounded fields, finite floats — malformed → 422 with a
  sanitized error body) and delegates to the composed monitor; breaches
  publish `ThreatThresholdExceededEvent`, non-breaches publish nothing;
  event-bus failure → explicit 503 (never silent).
* **Producer/consumer envelope fix** — `RedisStreamPublisher` now XADDs
  the field set `RedisIncidentEventConsumer._deserialize` actually reads
  (`event_id`, `event_type`, `aggregate_id`, `timestamp`, `payload` as
  JSON string). Previously the single `data` field would have been
  acknowledged and dropped — the live chain could never connect.
* **Observability** — structured `monitoring.threshold_exceeded` marker
  (event_id/service/metric/value/threshold/correlation id; ids+numbers
  only). Optional observation `metrics` context passes through the
  pre-existing `payload.metrics` envelope key the incident handler
  already reads — no new schema fields.
* **Compose** — monitoring-service gains event-bus env + `depends_on:
  redis` (still no host ports; gateway-only publication preserved).
* **Tests** — producer test updated to the consumer envelope + real
  deserializer round-trip; new `tests/test_monitoring_runtime_slice.py`:
  composition/config unit tests, ingestion contract (publish, no-breach,
  malformed 422, bus 503, prompt-injection-as-data), and the vertical
  slice `monitoring input → event → consumer → incident (duplicate-event
  idempotent) → deployment evidence → RCA → persisted proposal` with
  no-side-effect spies across the whole chain.

## 2026-09-27 — Phase 6.1: incident → evidence → RCA → structured remediation proposal

Proposal-only pipeline inside `devops-ai-platform/incident_service` (no
execution of any kind — no clone/modify/commit/push/branch/PR, no deploy,
no remediation engine, no approval).

* **Producer wiring:** `ThresholdValidator` can publish
  `ThreatThresholdExceededEvent` via the new shared
  `RedisStreamPublisher` (`devops:events`) — the exact type the incident
  consumer already dispatches.
* **Idempotent ingestion:** incident and threshold-evidence ids derive
  from the producer `event_id` (uuid5); redeliveries return the existing
  incident without duplicates; proposal regeneration upserts one record.
* **Typed RCA:** `RootCauseAnalysis` domain object persisted as
  `kind="rca_result"` evidence; `RcaAnalyzerPort` (agent-service adapter,
  deterministic fakes in tests); `parse_rca_result` schema fail-closed
  (bounded types/lengths, confidence in [0,1], evidence refs must exist
  on the incident; legacy `supporting_evidence_ids` alias supported).
* **Trusted target binding:** `resolve_authoritative_deployment_target`
  reuses the Stage-5 gates (DEPLOYED, one-record canonical repo + 40-hex
  SHA, valid provenance); no trustworthy target → persisted
  `BLOCKED/MISSING_DEPLOYED_TARGET_EVIDENCE` proposal with empty identity
  fields — nothing fabricated.
* **Proposal generation:** AI may propose file/patch/plan/risk only;
  target-path policy + `HotfixProposal.apply_verification_pass()` +
  `HotfixValidationService` decide pass/fail (single-file policy kept);
  deterministic `LOW|MEDIUM|HIGH|BLOCKED` risk classifier; SHA-256
  canonical proposal hash over the fixed §18 field set; every §12 field
  survives repository reload; success → incident `RemediationProposed`.
* **API:** `POST/GET /incidents/{id}/proposal` (typed failures: 404/422/
  503) + gateway `GET /v1/incidents/{id}/proposal` (JWT + operator role).
* **Observability:** structured single-line JSON logs (`incident.created`,
  `evidence.attached`, `rca.started/completed/failed`,
  `proposal.generated/validated/blocked`) with correlation ids; no
  secrets, tokens or full AI outputs logged.
* **Tests:** incident suite grows 17 → 21 modules (140 tests), platform
  `tests/` gains the producer + full pipeline E2E; gateway read-route
  auth matrix added. Full local battery: 323 tests + 91 subtests green;
  §22 no-side-effect spies assert GitHub client/git/branch/PR/deploy/
  remediation-engine paths are never invoked while the proposal is still
  produced and persisted.

## 2026-09-24 — Development round: fix & stabilize (post-forensic-audit)

This round addresses the defects identified in `FORENSIC_REPORT.md`.
All changes verified by the test suites below (no Docker/Android SDK in CI,
so Python is exercised end-to-end and Android changes are compile-safe edits).

### P0 — critical fixes

* **Client ↔ backend contract now works.** Added `GET /api/v1/health`,
  `GET /api/v1/repositories` and `POST /api/v1/repository/analyze` to
  `backend/app/main.py`. The last returns the exact 5-field shape the Android
  `BackendGatewayClient` parses (`dockerfile`, `k8s_yaml`, `terraform_tf`,
  `pipeline_yaml`, `analysis_report`), upserts the repo row, and runs live
  Gemini server-side when `GEMINI_API_KEY` is set (key sent via the
  `x-goog-api-key` header, never as a URL query param). The remote-backend
  feature in the app is now functional end-to-end.
* **Preset duplication bug fixed** (`DevOpsRepository.setupPresetsIfEmpty`):
  the always-null `getRepoByPredicate` helper is gone; seeding now gates on a
  real `COUNT(*)` DAO query. New Robolectric+Room regression test asserts
  presets exist exactly once after repeated seeding.
* **`devops-ai-platform` is now bootable.**
  * All 7 hyphenated service directories renamed to valid Python packages
    (`api_gateway`, `repo_service`, `agent_service`, `deployment_service`,
    `monitoring_service`, `incident_service`, `reporting_service`);
    `__init__.py` added throughout.
  * `shared-kernel/` merged into the importable `shared_kernel/` package
    (events, value objects, messaging, metrics).
  * Every `main.py`/entrypoint that was missing now exists; each service has
    a Dockerfile; `docker-compose.yml` builds and runs the full stack with
    service names/ports matching the gateway routing matrix.
  * Broken imports fixed: `execute_deployment.py` now imports a real
    `deployment_service/domain/exceptions.py` (duplicated class removed);
    all cross-service `shared_kernel` imports corrected (relative-depth bugs →
    absolute imports); `mcp/mcp_server.py` `logger` NameError fixed.

### P1 — hardening & quality

* **Real gateway JWT auth** (`api_gateway/core/auth.py`): the "any token ≥ 10
  chars = Developer, literal = admin" mock is replaced with HS256
  sign/verify (stdlib crypto) using the previously-dead `JWT_SECRET`,
  expiry enforcement, constant-time compare, and a token-mint CLI
  (`python -m api_gateway.core.auth <sub> [roles...]`). Startup warns when
  the committed dev fallback secret is in use.
* **`/metrics` on the root gateway** (`prometheus_client`): the Prometheus
  target in `monitoring/prometheus.yml` is now real; a Qdrant job was added.
  **Grafana** now provisions its Prometheus datasource on boot.
* **Honest gateway dispatch** (`api_gateway/routers/gateway_router.py`):
  `/v1/gateway/dispatch/{service}` performs a real HTTP forward and reports
  502 when the downstream is down instead of fabricating `PROXY_PASSTHROUGH`.
* **Sentry webhook HMAC** (`incident_service`): `X-Sentry-Signature` is
  verified as HMAC-SHA256 over the raw body when `SENTRY_WEBHOOK_SECRET` is
  set (401 otherwise); permissive dev mode only when unset, with a warning.
* **GitHub PR client no longer fabricates success**: missing
  `GITHUB_OAUTH_TOKEN` raises `InvalidGitHubTokenException` instead of
  returning a fake PR URL.
* **Qdrant boot no longer destructive**: create-if-missing instead of
  `recreate_collection` on every startup (vector data survives restarts).
* **CORS correctness**: wildcard origins no longer combined with
  credentials; origins configurable via `CORS_ORIGINS`.
* **Android health probe honesty** (`BackendGatewayClient.testConnection`):
  probes `/health` then `/api/v1/health`; only 2xx counts as connected —
  404-as-success removed.
* **`analyzeRepoAsync`** now updates the repo row instead of re-inserting a
  copy to set `Analyzing`.
* **Tests added:**
  * `backend/tests/` — 33 tests (API contract, /metrics, CORS, Celery
    fallback path, tag protocol parsing, Gemini live path with mocked
    transport incl. key-in-header assertion).
  * `devops-ai-platform/tests/` — 20 tests (boot + auth + HMAC + SSE/WS +
    guardrail regressions).
  * Android — `GeminiClientParseTest` (8 parse-tag cases),
    `DevOpsRepositorySeedingTest` (2 seeding regressions);
    `ExampleRobolectricTest` assertion corrected to the real app name;
    the non-compiling `GreetingScreenshotTest` (referenced a composable that
    never existed) and its stale baseline removed.
* **CI** (`.github/workflows/ci.yml`): backend + platform pytest jobs on
  push/PR.

### P2 — misc

* `celery_worker.py` reuses the shared template engine (single source of
  truth for IaC templates across sync/async paths; tech branching now
  python/node/JVM, matching the app).
* `GeminiClient.parseTag` made `internal` for direct unit testing.
* Pydantic v2 (`ConfigDict`) and SQLAlchemy 2.0 import modernizations;
  deprecated `@app.on_event` replaced by lifespan.
* `backend/.dockerignore`-style hygiene: `.gitignore` extended
  (`__pycache__`, `.venv`, `*.sqlite3`, …).
* Docs corrected: `VS_CODE_AND_VERCEL_ROADMAP.md` (real uvicorn paths, real
  env vars — the Prisma-style `POSTGRES_PRISMA_URL`/`REDIS_URL` phantoms are
  gone), `README.md` (honest simulation labels, backend + platform setup),
  new `devops-ai-platform/README.md`.

### Still open (tracked in FORENSIC_REPORT.md §34)

* Verify `gemini-3.5-flash` / `gemini-3.1-pro-preview` model ids with a real
  key (still 🔴 unverified upstream).
* gRPC surfaces still lack `.proto` files and registered servers.
* Real Postgres adapters for the platform services (still stubs by design).
* Room schema export / Alembic migrations (both stacks still `create_all`).
* Android build verification (no JDK in this environment) — run
  `gradle assembleDebug` + `gradle :app:testDebugUnitTest` on a dev machine.
