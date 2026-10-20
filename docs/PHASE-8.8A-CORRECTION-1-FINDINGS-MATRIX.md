# Phase 8.8A Correction-1 — Finding → File → Test Matrix

Work log (untracked). Branch `arena/phase-8-8a-correction-1-runtime-security`
from `a417467` (verified unchanged on origin; CI 39059246013 11/11 green at that SHA).

Every finding was re-verified against `a417467` source before editing (2026-10-18).

## F1 — canonical runtime: Celery-only image vs HTTP healthcheck

| Evidence at a417467 | |
|---|---|
| `deployment_service/Dockerfile` CMD | `celery -A ... worker` only |
| `devops-ai-platform/docker-compose.yml` `deployment-service` | healthcheck `http://127.0.0.1:8030/health` — nothing listens → container can never be healthy |
| `Dockerfile.e2e` CMD | celery **and** uvicorn (different runtime) |
| ci.yml `compose-runtime` readiness step | asserts gateway + agent only; never deployment-service health |

**Changes:**
- `deployment_service/Dockerfile` → pinned base (F6) + `CMD uvicorn deployment_service.main:app --port 8030`.
- `docker-compose.yml` → split into `deployment-api` (container_name **`deployment-service`**, port 8030 exposed-internal, HTTP health, **no docker socket**) and `deployment-worker` (same image, `command:` celery worker, `celery inspect ping` healthcheck, **no socket in canonical**).
- `docker-compose.e2e.yml` → overrides retargeted to both services; only the disposable worker gets socket + kubeconfig + staging + execution-enabled.
- ci.yml `compose-runtime` readiness: api healthy, worker ready, `deployment-service:8030/health` via compose network, authenticated 401/404/422 probes, execution-disabled assertion, no socket on api, image digest in evidence JSON; job fails on unhealthy.
- `main.py` `/health`: real readiness (redis ping + execution flag + auth config state).

**Tests:** CI compose assertions; `tests/test_deployment_api_contract.py` (health contract); compose job negative property (worker-only image ⇒ health absent ⇒ job red — the healthcheck itself is the negative test, asserted in CI).

## F2 — no caller authentication/authorization on deployment API

| Evidence at a417467 | |
|---|---|
| `main.py` | 4 sensitive routes, zero auth dependencies; `ApprovalRequest.approved_by` = caller-supplied text |
| gateway `core/auth.py` | existing HS256 contract (JWT_SECRET, sub+roles+exp, fail-closed 503, operator roles) to reuse |

**Changes:**
- New `deployment_service/application/services/deployment_auth.py`: HS256 verify (same contract as gateway), internal service token via `AGENT_INTERNAL_TOKEN` (constant-time compare, min length, fixed principal `service`), role policy, fail-closed config (503, never a bundled secret).
- `main.py` → `create_app()` factory (startup: execution-enabled ⇒ JWT_SECRET required); deps on dry-run / read / approve / execute; `approved_by` derived from verified `sub` (body field removed; a legacy body value is ignored, never trusted); inspection visibility (creator or operator); stable 401/403/404/409/503; no token/secret leakage in errors.
- `DeploymentRun` + `created_by`.

**Tests:** new `deployment_service/tests/test_deployment_auth.py` (full 401/403 matrix: missing/invalid/expired/wrong-signature/wrong-role/missing-config/spoofed-approved_by/cross-creator/disabled-execution); existing `test_internal_deployments_api.py` + `test_deployment_http_contract.py` updated to authenticated calls.

## F3 — Kubernetes sandbox network validation fails open

| Evidence at a417467 | |
|---|---|
| `container_kubectl_sandbox.py::_validate_network` | `peers = approved_peers_from_environment(); if not peers: return` — empty/missing config = no validation |
| `kubernetes_sandbox_network.py::validate_network` | `unexpected = [... if m not in permitted and not m.startswith("ares-kubectl-")]` — prefix acceptance |

**Changes:**
- `kubernetes_sandbox_network.py`: exact allow-list only (prefix removed); peer names validated (DNS-1123 container-name pattern); empty/missing/malformed peer set = hard policy error (new exception type); `PerExecutionNetwork.create` refuses empty peer set.
- `container_kubectl_sandbox.py`: network validation BEFORE any staging/credential material is written; empty peers ⇒ raise, never return.
- `kubectl_runner.py`: mutating operations re-verify network identity immediately before the sensitive step (TOCTU window).

**Tests:** extend `test_sandbox_network_isolation.py`: missing env, empty value, malformed value, inspection failure, unknown network, missing expected peer, one extra peer, malicious same-prefix peer, wrong network id, identity substitution, concurrent sharing. CI probes in `scripts/mutation_probe_kubernetes_boundary.py` (new: empty-peer fail-open + prefix bypass).

## F4 — staged kubeconfig world-readable (0444 / dir 0711)

| Evidence at a417467 | |
|---|---|
| `container_kubectl_sandbox.py::execute` | `os.chmod(kubeconfig_path, 0o444); os.chmod(staging, 0o711)` — comment even justifies it |
| `e2e/kubernetes_service_http_kind_e2e.py:236/737` | host kubeconfig 0644; STAGING_ROOT 0711 |

**Changes:**
- `container_kubectl_sandbox.py`: staging root must be private (0700, owned by worker identity, no pre-existing attacker-controlled path, symlink rejection in parent chain); per-run dir 0700; kubeconfig **chown to sandbox uid:gid + 0600** (the sandbox user 65532:65532 reads it; every other host user cannot) — chown failure ⇒ abort, never a 0444 fallback; O_EXCL writes (existing) kept; safe cleanup that cannot follow symlinks or leave the owned root.
- E2E driver: STAGING_ROOT 0700, host kubeconfig 0600; live cross-UID proof via `setpriv` (uid 65532 reads OK; unrelated uid denied) on Linux CI.

**Tests:** new `deployment_service/tests/test_kubeconfig_staging_permissions.py` (mode/owner bits, symlink/traversal/pre-existing-path rejection, cleanup on success/error/timeout; the unprivileged-read case runs where a non-root user exists and is otherwise a documented skip). The real cross-UID proof in CI is the E2E driver's `sudo -u nobody cat` attempt against a 0700/0600 staged layout on the runner (must fail) plus the owner read (must succeed).

## F5 — Redis lease: constant token "1", unconditional DEL, no renewal, TTL < budgets

| Evidence at a417467 | |
|---|---|
| `redis_pipeline_store.py` | `set(..., "1", nx=True, ex=900)`; `release_lock` = bare `delete` |
| budgets | terraform apply 600s + k8s apply 300s + rollout 330s (+180 undo) > 900s |

**Changes:**
- New `infrastructure/persistence/execution_lease.py`: atomic Lua acquire `SET owner-token NX PX ttl`, compare-and-delete release, compare-and-expire renewal, monotonic per-run fencing token (INCR), fence-guarded state commit (CAS), renewal watchdog (bounded interval, outage ⇒ lease-lost event + bounded sandbox cancel).
- `redis_pipeline_store.py`: constant-token lock replaced by the lease; fence-aware `save`.
- `deployment_engine.py::execute`: guard checks before every side effect and before every commit; lost lease ⇒ bounded cancel + `LEASE_LOST` (new terminal state), stale worker commits nothing.
- `celery/tasks.py` + `main.py /execute`: worker-owned execution; idempotent under at-least-once (terminal state ⇒ return persisted outcome; held lease ⇒ refuse duplicate); dispatch failure ⇒ truthful refusal, run back to APPROVED, never "accepted".
- `DeploymentState` + `EXECUTION_REQUESTED`, `LEASE_LOST` (edges: APPROVED→EXECUTION_REQUESTED→DEPLOYING; EXECUTION_REQUESTED→APPROVED on dispatch failure; {DEPLOYING,HEALTH_CHECKING,ROLLBACK_PENDING}→LEASE_LOST terminal).

**Tests:** new `deployment_service/tests/test_execution_lease.py` (REAL Redis, `REDIS_URL` contract + `REDIS_INTEGRATION_REQUIRED` hard-fail in CI): owner A expires / B acquires; A's release cannot delete B's key; A's renewal fails; stale fence cannot commit or start next operation; long run renews; Redis outage during renewal ⇒ blocked; 20+ concurrent duplicates ⇒ one executor; crash+redelivery ⇒ no double-apply. Wired into the redis-integration job.

## F6 — floating `python:3.11-slim` in the canonical image

| Evidence at a417467 | |
|---|---|
| `deployment_service/Dockerfile` | `FROM python:3.11-slim` |
| approved digest | `e2e/pinned-images.txt`: `python:3.11-slim sha256:0dd364ba7e10242f07755449e3a3d0e35f9efd987952737b90def6709ab0c5ce` (fetched 2026-10-06 from registry.hub.docker.com; live-pulled by every CI E2E build) |

**Changes:**
- Canonical Dockerfile `FROM python:3.11-slim@sha256:0dd364...` (the repository's already-approved digest; CI re-pulls it on every build — live verification loop).
- New `scripts/assert_deployment_base_images.py`: rejects floating/untagged bases in `deployment_service/Dockerfile` and `Dockerfile.e2e` (must be ARG); canonical digest must equal the committed pin.
- CI: guard step in `terraform-trust-boundary` + `compose-runtime`.

**Tests:** guard script (clean tree ⇒ 0); mutation M37 (float the base ⇒ guard red).

## F7 — two execution pathways (HTTP direct + Celery task)

| Evidence at a417467 | |
|---|---|
| `main.py /execute` | calls `engine.execute(...)` synchronously |
| `tasks.execute_iac_deployment` | also calls `engine.execute(...)` |
| canonical image | worker-only ⇒ HTTP path unreachable in canonical runtime |

**Changes (one explicit contract):**
- API = validate (state, hashes, namespace, execution-enabled) + persist `EXECUTION_REQUESTED` + enqueue + return truthful `queued` with the real persisted run id.
- Worker = acquire lease (owner token + fence) + reload durable run + re-check authorization/approval/digests + invoke engine + persist each transition.
- Dispatch/persistence failure ⇒ 409/503 + run reverted to APPROVED; never accepted/completed/SUCCESS.
- At-least-once delivery documented; worker idempotent (no exactly-once claim).
- E2E drivers (terraform + http) adapt: execute ⇒ queued, poll `GET /{run_id}` to terminal.

**Tests:** `tests/test_deployment_api_contract.py` (queued response, broker-down refusal, duplicate dispatch refused, redelivery idempotency, terminal-state short-circuit); E2E drivers' live assertions in CI.

## Mutations (next free IDs; M1–M32 unchanged in intent)

| ID | Mutation (isolated copy) | Detector |
|---|---|---|
| M33 | `compare_digest` → `startswith(expected[:10])` in `deployment_auth.py` (internal-token prefix bypass) | behavioral: the mutated module accepts a 10-char prefix token; the real module refuses it |
| M34 | `approved_by: Optional[str]` restored to `ApprovalRequest` + route passes `request.approved_by or identity.subject` (caller-supplied approver) | `test_deployment_auth.py -k approver` on the mutated copy |
| M35 | `approved_peers_from_environment()` → `return ()` on empty/malformed env (fail-open) | `test_sandbox_network_isolation.py -k "empty_peer_env or missing_peer_env or whitespace_peer_env"` |
| M36 | `if stored_state in _TERMINAL_STATES:` → `if False:` in `infrastructure/celery/tasks.py` (terminal-redelivery re-execution) | `test_deployment_api_dispatch_contract.py -k "redelivery or concurrent_duplicate"` |
| M37 | `_CREDENTIAL_MODE = 0o600` → `0o444` in `container_kubectl_sandbox.py` (world-readable staged credential) | `test_kubeconfig_staging_permissions.py -k "staging_layout_is_private or peer_cannot"` |

Additional mutation evidence (not pytest-mutation IDs):
- **Lease weakening** (constant token / unconditional DEL): covered behaviorally by the 9 real-Redis
  scenarios in `test_execution_lease.py` — compare-and-delete/compare-and-expire are asserted
  directly, so the weakened constant-token variants cannot pass the suite.
- **Floating base image**: `scripts/assert_deployment_base_images.py` verified against a mutated
  Dockerfile in a scratch copy (clean tree ⇒ 0; floating tag ⇒ 1), and wired into the
  structural-guards job as a standing gate.

## Jobs (hand-merged; no job removed)

1. security-integrity — full suite now includes new auth/contract/network/permission/lease tests; M33–M37 run here.
2. android-unit-tests — unchanged.
3. android-secret-guards — unchanged.
4. structural-guards — + base-image digest-parity step (F6, `scripts/assert_deployment_base_images.py`); + runtime_guard lease-step contract.
5. redis-integration — + execution-lease safety step against the live store (F5, 9 scenarios, fail-closed flag).
6. compose-runtime — + F1 readiness assertions (API /health contract incl. redis ok + execution disabled, worker celery ping, anonymous 401 / authenticated 404); build covers `deployment-api` + `deployment-worker`.
7. terraform-trust-boundary — unchanged.
8. terraform-sandbox-container-e2e — topology validation step (both services); driver: operator JWT, truthful dispatch + poll-to-terminal.
9. kubernetes-trust-boundary — unit run now includes `test_sandbox_network_isolation.py` + `test_kubeconfig_staging_permissions.py`; + 6 new k8s probes (empty-peer, malformed-peer, prefix-bypass, staging fallback/adopt/symlink).
10. kubernetes-kind-e2e — driver-level (staging 0700, kubeconfig 0600).
11. kubernetes-service-http-e2e — driver: per-run random JWT + operator token on every call, async execute (dispatched=true, EXECUTION_REQUESTED) + poll to terminal state, real `nobody` peer-read proof of the 0700/0600 staged credential.

## CI resolution record (post-1fcb278, session branch)

The correction branch's first two CI runs were red; the root causes found
(and the commits that fixed them, all on the session branch):

1. **7137f5e** — compose readiness exec used the pre-split service name
   (`deployment-service` → `deployment-api`); the Celery worker's task-time
   import path lost the platform root (celery's `cwd_in_path()` inserts and
   later removes the cwd, so a guarded `sys.path` pin in the -A module never
   fired — the pin is now unconditional in `celery/tasks.py`); the kind E2E
   driver did not set `DEPLOYMENT_K8S_SANDBOX_PEERS` (now fail-closed, so the
   driver names the single approved peer); the auth test's store construction
   was made deterministic (`_FakeStore`).
2. **231c770** — the launch seam of `container_kubectl_sandbox.py` had two
   latent NameErrors invisible to unit tests (the tests patch the launch seam)
   and to the mutation probes (they stop at the network/staging boundary):
   `_monotonic()` referenced but never defined (first real sandbox launch),
   and `KubectlSandboxResult(operation=step.operation)` built without `step`
   in scope (success path). Reproduced in-situ with a fake docker runtime:
   the dry run then reached AWAITING_APPROVAL. The dry-run handler now records
   the exception message, not only the type.
3. **4b8ab82** — three distinct causes surfaced via the new failure
   annotations: (a) the kind E2E driver runs the sandbox on the non-root CI
   runner, and F4 staging chowns the credential to the sandbox identity —
   impossible unprivileged. The proven F4 property is that the sandbox
   process's uid owns the 0600 credential; on a non-root proof host the
   sandbox now runs as the driver's own identity (chown-to-self), root keeps
   the least-privilege nobody. (b) The F7 dispatch-contract tests exercise
   the real durable store by design; the security job now starts the same
   digest-pinned redis:7.2-alpine as the redis-integration job. (c) The http
   driver used `shutil` in teardown without a module-level import.
4. **514be7f / bb5eca3** — digest transcription error (a 65-char redis digest
   in the new step; the correction briefly touched the wrong line) restored to
   the exact 64-char digest verified green previously, checked
   programmatically; and the if-always publish step's `grep | head` pipeline
   (exit 1 on a GREEN suite under pipefail) made red by its own diagnostics —
   the no-match case is now explicit.

Final state: CI run **39074230769** at **bb5eca3** — 11/11 jobs green at the
exact SHA, including live Compose boot/readiness, real-Redis integration
(execution lease, 9 scenarios), containerized terraform E2E, live Kind
kubernetes E2E (driver-level staging proof, non-root sandbox identity) and the
service→HTTP→Kind E2E at **36/36 PASS** (real dispatch, worker-owned
execution, terminal DEPLOYED on Kind, deterministic health verification).

## Independent audit follow-up (2026-10-20, three P1 issues)

Fixed one at a time on the session branch, each with regression tests and
CI green at the exact SHA.

### P1-1 — Celery crash recovery (commit 2cf0f53; CI 39377033703, 11/11 at SHA)

* `infrastructure/celery/tasks.py` — explicit broker semantics
  (`acks_late`, `acks_on_failure_or_timeout=False`,
  `reject_on_worker_lost`, prefetch 1, `retry_on_startup`, visibility
  3600 s > the 2790 s bounded worst case); explicit `-P prefork
  --concurrency=1` at every worker launch site (Dockerfile.e2e CMD,
  canonical compose).
* `tests/crash_recovery_worker_target.py` + `tests/test_celery_crash_recovery.py`
  — real worker subprocesses on the live broker, SIGKILL mid-execution,
  restart, redelivery of the unacked message, idempotent resume
  (SUCCEEDED) and terminal duplicate REPLAY with zero work. CI step
  "Celery crash recovery — worker kill/restart on the live broker (audit
  P1)", evidence artifact `celery-crash-recovery.txt`.
* Structural guard `_check_redis_integration_contract` now covers the 4th
  live-store step; mutation M24 updated to count it (extends, does not
  reduce).

### P1-2 — safe dispatch semantics (ambiguous broker publish, duplicate
requests, concurrent transitions, retries, worker/API races)

The old contract conflated "the broker accepted the task", "the broker
never received it" and "we do not know which": any publish exception
triggered an UNGUARDED read-check-write revert and a 503 claiming
"nothing was executed" — false whenever the timed-out publish had in
fact queued the task.

**Independent audit (2026-10-20) of the first P1-2 fix (f2edf91): NOT
CLOSED — four blockers, all corrected in the follow-up:**

* **Blocker A** — the initial APPROVED -> EXECUTION_REQUESTED
  preparation was still an unguarded read/check/write: two concurrent
  /execute requests could both claim and both publish.
* **Blocker B** — redeliver_dispatch wrote a stale whole document with a
  plain save (a worker could advance between read and save).
* **Blocker C** — the CAS guard checked state + dispatch id + fence but
  no document version, so same-state concurrent writers could reset
  each other's bookkeeping.
* **Blocker D** — a broker reachability ping was used as the revert
  gate; a ping cannot prove that a FAILED publish was never accepted
  (the broker may accept and then die), so reverting an ambiguous send
  to APPROVED was unsafe.

**Follow-up fixes (all in the same focused set of files):**

1. **Monotonic document revision (A/B/C).** The run document's revision
   lives in a separate counter key (`deployment_run:<id>:rev`) bumped
   inside the SAME Lua script that performs every durable write:
   `store.save`, the new `store.save_cas`, `store.cas_run_document`,
   and the lease's fenced `COMMIT_SCRIPT` (a worker state-advance is
   therefore visible to every API-side claim). The document bytes are
   stored AS-IS — never decoded/re-encoded (an earlier draft re-encoded
   through Lua cjson, which corrupts empty arrays to `{}`; rejected and
   replaced). A writer that read revision N cannot overwrite a document
   written after its read, whoever wrote it: the dispatch claim,
   re-dispatch, revert and outcome bookkeeping are all
   compare-and-set on the revision, and the losing concurrent request
   publishes nothing.
2. **Conservative failure classification (D).** A failed publish is
   AMBIGUOUS by default — a timeout, a mid-command disconnect, an
   unknown error, or any exception chain with a timeout anywhere in it
   proves nothing about acceptance. The ONLY revertible class is
   provably PRE-SEND: every attempt failed with a clean TCP-level
   connection REFUSAL (no publish bytes could have reached the broker).
   No reachability probe gates any revert: an ambiguous send is NEVER
   reverted to APPROVED, even if the broker is unreachable right now;
   it stays EXECUTION_REQUESTED (durable, flagged `ambiguous`) for
   idempotent re-dispatch.

**Second independent audit (2026-10-20) of the follow-up: one P1
failure-path gap remained in Blocker D — corrected:**

* **Residual hole** — the revert decision inspected only the CURRENT
  HTTP call's publish errors. A dispatch whose EARLIER attempt was
  ambiguous (or even successful) could be reverted to APPROVED by a
  later re-POST whose retries all failed pre-send — erasing the history
  that the earlier task may still be queued.
* **Fix** — a durable, MONOTONIC dispatch-history fact
  `may_have_been_published`, persisted with the dispatch record: set by
  any successful or ambiguous publish, never cleared. The revert is
  refused both at the route decision (the persisted history is
  consulted) and in the Lua CAS (`require_not_maybe_published`),
  no matter what later retries show; the run then stays
  EXECUTION_REQUESTED, explicitly ambiguous, and remains eligible for
  idempotent same-id re-dispatch. A fresh run whose ENTIRE history is
  pre-send still reverts truthfully (503, "nothing was executed").
* **Tests (suite now 24, all live-Redis)** — ambiguous initial publish
  then a re-POST with all-pre-send refusals: NOT reverted, history
  preserved, no false "nothing was executed" claim; successful publish
  then stale then all-pre-send refusals: NOT reverted (the original
  task may still be queued); broker-backed acceptance: the message is
  real-published to the live broker and independently verified in the
  queue (the BRPOPped envelope carries the stable task id + run id a
  real worker would execute), with producer-side confirmation loss
  injected AFTER the real publish; the accepted-then-error unit tests
  are labeled as simulations.
* **Wording correction (audit accuracy note)** — every durable write
  ADVANCES the revision; the concurrency-sensitive dispatch writes
  (claim, re-dispatch, revert, outcome bookkeeping) are CAS-guarded on
  it. Unconditional saves (single-writer phases, worker state
  advances) advance the counter too, invalidating dispatch claims
  based on earlier reads — but they do not check it.

Files (focused, no architectural change):

* `deployment_service/infrastructure/persistence/redis_pipeline_store.py`
  — revision counter + `save_cas` (claim) + `cas_run_document` (Lua
  compare-and-set guarded on state + dispatch identity + revision
  counter + absence of a worker fence `deployment_fence_active:<run_id>`;
  document bytes stored as-is). Returns False (never raises) when the
  run moved on or the claim was lost.
* `deployment_service/application/services/deployment_engine.py`
  — `prepare_dispatch` now persists a DURE DISPATCH record
  (`execution.dispatch = {dispatch_id, task_id, attempts,
  last_attempt_at, ambiguous}`) BEFORE the publish; `dispatch_id` is the
  stable celery `task_id`. New `redeliver_dispatch` (idempotent re-publish
  of the SAME task id, allowed only when the dispatch is AMBIGUOUS or
  STALE — > 2x the broker visibility timeout — with re-verified hashes)
  and `revert_dispatch(run_id, dispatch_id)` (atomic via
  `cas_run_document`; returns whether the revert applied) plus
  `record_dispatch_outcome` (CAS-guarded ambiguity bookkeeping that can
  never clobber an advanced run).
* `deployment_service/main.py` — `/execute` is tri-state:
  * 200 `dispatched: true` — publish completed (bounded 3 attempts, same
    task id);
  * 200 `dispatched: "unknown"` — publish failed while a bounded
    reachability probe found the broker REACHABLE (ambiguous timeout):
    the run is NOT reverted, stays EXECUTION_REQUESTED, and re-POSTing
    the same request idempotently re-publishes the SAME stable task id;
  * 503 — publish failed AND the probe confirmed the broker DOWN: atomic
    CAS revert to APPROVED, truthfully "nothing was executed"; if the CAS
    declines (the run moved on), the API reports the run's CURRENT state
    instead.
  A fresh (non-ambiguous, non-stale) EXECUTION_REQUESTED duplicate stays
  409 — exactly-once dispatch on the normal path is preserved.

Regression tests (`deployment_service/tests/
test_deployment_api_dispatch_contract.py`, all against the live store;
21 total, 13 added across the two rounds):

* ambiguous publish → 200 `"unknown"`, run kept EXECUTION_REQUESTED,
  `ambiguous` persisted, 3 bounded retries all with the same task id;
  re-POST → 200 true, SAME task id, attempts=2, ambiguity cleared;
* stale dispatch (last attempt > 2x visibility) → idempotent
  redelivery with the same task id;
* re-dispatch with a mismatched artifact hash → 409, nothing enqueued;
* terminal run + execute → 409, run not resurrected;
* revert-CAS is a NO-OP (never a clobber) when the run already advanced
  (DEPLOYING), when a worker fence is active, or when the dispatch
  identity differs;
* existing contract tests preserved (fresh duplicate 409, pre-send
  broker refusal 503 + APPROVED revert, worker terminal redelivery
  replay, concurrent ALREADY_EXECUTING);
* audit acceptance tests (all live-Redis, deterministic):
  1. two concurrent /execute HTTP requests from the same APPROVED
     document, barrier-synchronized at the claim phase: exactly one
     claim wins (200), the loser is refused (409) and publishes
     nothing; the winning dispatch identity is the one published;
  2. redelivery read at revision R, a worker advances the run to
     DEPLOYING in the window, the stale write is refused — the worker's
     state and the dispatch record stand; the method itself then
     refuses too;
  3. broker accepts the message, producer then times out (broker now
     unreachable): 200 "unknown", run NOT reverted, ambiguous flag
     set — no "nothing was executed" claim;
  4. publish accepted, broker outage before any probe: no unsafe
     revert (the probe no longer gates a revert at all);
  5. mixed attempts (pre-send refusal + mid-command reset): any
     ambiguous attempt makes the whole outcome ambiguous;
  6. two writers reading the same revision (a redelivery vs a stale
     outcome): exactly one applies; the stale one cannot reset the
     attempt count/timestamp/ambiguity fields (retried, refused again).

Documented residual limitation (cannot be eliminated without a broker
delivery-ack, which Redis does not provide): an ambiguous-but-lost
message is recovered by idempotent re-dispatch, which becomes eligible
automatically as soon as the dispatch is marked ambiguous (immediate
re-POST) or ages past 2x the visibility timeout (7200 s). There is no
autonomous relay process: the caller (pipeline runner) re-POSTs. Because
redelivery reuses the stable task id and the worker's fenced lease +
terminal-state check absorb duplicates, at-least-once delivery never
becomes double execution. The pre-send classification is
transport-signature based (connection-refused at connect time); any
failure that cannot be proven pre-send is treated as ambiguous — the
safe side: the run is never reverted, at most an extra idempotent
re-dispatch happens.

### P1-3 — lease-loss safety (stale worker after re-grant)

NOT STARTED: pending after P1-2 review. Planned: a stale worker must not
initiate another external side effect after losing its lease;
deterministic race test (expire old lease → grant new fencing token →
resume old worker).
