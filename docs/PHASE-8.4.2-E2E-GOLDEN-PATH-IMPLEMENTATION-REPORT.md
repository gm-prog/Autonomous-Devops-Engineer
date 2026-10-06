# Phase 8.4.2 — Full CI-Venue Golden-Path Harness & Hostile E2E Verification

## Executive result

```text
PARTIAL — HARNESS IMPLEMENTED / CI E2E NOT VERIFIED
```

The complete CI-hosted golden-path system is implemented, unit-tested
and CI-green at the exact head, but **no golden-path workflow run has
been executed**: the external prerequisites (disposable fixture
repository, restricted fixture token, protected `e2e-staging` secrets)
cannot be provisioned from this executor — its GitHub credential is a
GitHub App installation token ("integration") that is refused for
repository creation and secret/environment management. Per §53/§57 this
is reported honestly rather than faked. No stage below is claimed PASS
on external evidence.

## Exact source

| Item | Value |
| --- | --- |
| Authoritative base (Phase 8.4.1 head) | `f518a171049556523d63208e2a48c8c20e221974` |
| Implementation commits | `1eedb5e` (§47 operator hardening + §48 seam documentation), `d16f2bd` (harness), `633cdfe` (harness unit tests) |
| Documentation commit | this file |
| `main` | `7b30a56d2bfd06798c0a90023acd1c6bd5cd3420` — **UNCHANGED** (re-verified) |
| Integration refs | **six integration refs** — 6 audited / 0 modified, byte-identical: `4bd799b3` (foundation), `3d87007d` (phase-8), `71713d83` (phase-8.1), `a0bf7600` (phase-8.2), `1184eb67` (reconciliation), `d1961e43` (remediation-reconstruction) |
| PRs #8–#11 | untouched (opened/closed/edited nothing) |
| Force-push / history rewrite | none |

## Workflow evidence

- Workflow file: `.github/workflows/e2e-golden-path.yml`
  (`workflow_dispatch` only; `environment: e2e-staging`;
  `permissions: contents: read`; `concurrency.group: e2e-golden-path`
  with `cancel-in-progress: false`; **no** `pull_request_target`; all
  third-party actions pinned to full commit SHAs —
  `actions/checkout@3d3c42e5…` and `actions/upload-artifact@043fb46d…`,
  both verified as v7.0.1 commit objects via the GitHub API before use).
- **Golden-path workflow run: NONE — NOT VERIFIED.** GitHub only allows
  `workflow_dispatch` of a workflow that exists on the default branch;
  merging this workflow to `main` is an owner action (forbidden to this
  session) and therefore part of the manual procedure below.
- Syntactic/semantic static verification performed instead:
  YAML parse OK (job/env structure), `bash -n` clean on **all 11 run
  blocks**, `${{ }}` expression balance check, SHA-pin audit, trigger
  audit, and validation that no `pull_request_target`/`cancel-in-progress:
  true` occurs. (actionlint binary download was blocked from the
  sandbox; GitHub will perform authoritative validation on push.)
- Harness-commit CI (existing five-job workflow, untouched):
  push run **`37444735354`** and PR run **`37444740296`** — both
  `success`, 5/5 jobs each, head `633cdfe`:
  `112206715102` Platform smoke tests ✓, `112206715391` Compose
  validation ✓, `112206715424` Backend tests ✓, `112206715438`
  Incident/RCA/remediation ✓, `112206715554` API gateway ✓ (PR-run job
  ids `112206731789/976/999/2070/2163` likewise ✓).

## Environment (configured vs observed)

| Component | State |
| --- | --- |
| Runner | `ubuntu-latest` (docker, compose v2, python3, go preinstalled) |
| Terraform | pinned `1.9.8`, official `SHA256SUMS` verified at run time |
| kubectl | pinned `v1.31.4`, official `.sha256` verified at run time |
| kind | pinned `v0.26.0` via `go install` (sumdb-verified); node image `kindest/node:v1.31.4` pulled then **digest-resolved before create** (recorded, never assumed) |
| Third-party compose images | `postgres:15-alpine`, `redis:7-alpine`, `qdrant/qdrant:v1.12.4`, `registry:2` — each pulled, digest-resolved, deployed as `name@sha256:…` (§8) |
| App images | built from exact checked-out source; deployment E2E image adds checksum-verified terraform+kubectl (production Dockerfile untouched); incident E2E image adds git + docker CLI for the real workspace/sandbox |
| Sandbox image | built locally, pushed to the local registry, used digest-pinned with `--pull never`; missing-image variant reserved for the §37 negative |
| kind cluster | code-owned `ares-e2e` (1 cp + 1 worker), not exposed; kubeconfig for deployment-service uses `https://ares-e2e-control-plane:6443` over the shared compose network (§11 model), cert SANs pinned in config |
| Fixture repository | **NOT CREATED — external prerequisite.** Required identity `gm-prog/ares-e2e-fixture`, seed content `src/service_config.py` = `SERVICE_NAME = "checkout-service"`. Attempted creation via this executor's token → `GraphQL: Resource not accessible by integration (createRepository)`. The harness verifies repo, seed SHA and exact seed content at preflight and fails BLOCKED otherwise. |
| Fixture token | **NOT VERIFIED.** The only credential available here can modify `gm-prog/Autonomous-Devops-Engineer` → stop condition §57 ("fixture token can reach the production repo"). It was deliberately NOT wired into the environment. |

## Stage ledger (external golden path)

Every stage below is **NOT VERIFIED** — harness implemented, no run.
(Design + in-repo evidence noted where it exists.)

| Stage | Status |
| --- | --- |
| protected `e2e-staging` environment + secrets | NOT VERIFIED (secrets unprovisionable here) |
| disposable fixture repo verified/written | NOT VERIFIED (creation blocked; preflight gate implemented) |
| compose boot + explicit readiness (postgres/redis/qdrant/gateway/4 services/worker group) | NOT VERIFIED (bounded probes implemented; local docker impossible in this sandbox) |
| kind cluster + in-container kubectl proof | NOT VERIFIED |
| zero-cloud terraform (fmt/init/validate/plan/apply via real engine) | NOT VERIFIED (fixture `terraform_data`-only config implemented; asserted PASS by real `IaCValidator` in unit tests) |
| deployment dry-run → approve → execute → DEPLOYED | NOT VERIFIED |
| monitoring HTTP → Redis → worker → incident | NOT VERIFIED |
| duplicate monitoring delivery (producer-event replay) | NOT VERIFIED |
| authoritative deployment evidence attach | NOT VERIFIED |
| networked RCA + hostile agent battery | NOT VERIFIED (same battery covered in-process by CI-green unit tests) |
| proposal + independent hash + mutations | NOT VERIFIED (covered in-process since 8.4.1) |
| stale/wrong-hash/foreign-identity approval negatives | NOT VERIFIED (in-process analogues green) |
| sandbox failure → restore → happy path | NOT VERIFIED |
| concurrency race / duplicate reconcile / branch tamper | NOT VERIFIED |
| commit parent / remote branch / draft PR / remote file | NOT VERIFIED |
| database cross-check | NOT VERIFIED |
| artifact bundle + secret-scan gate | NOT VERIFIED (gate implemented) |

## Evidence IDs

None — no golden-path run executed. Manifest schema
`ares.e2e.golden-path/1` is enforced by unit tests; the driver writes
`e2e-manifest.json` with `result` ∈ {PASS, FAIL, BLOCKED,
NOT_VERIFIED} only after observed assertions (never on speculation).

## Hostile matrix (§45) — coverage source

| Case | Expected | Coverage now |
| --- | --- | --- |
| no JWT | 401 | in-process (CI green) + driver step (not run) |
| non-operator mutation | 403 | in-process + driver step |
| fake approved_by | JWT identity wins | in-process + driver step |
| fake repository/source SHA in evidence request | ignored | in-process (8.4) + driver step |
| fake branch/command/argv | ignored | driver step (pydantic-fixed contracts) |
| foreign evidence citation | 422 | in-process + driver agent battery |
| non-breaching signal (equal/below) | no RCA conclusion | in-process + driver agent battery |
| wrong service / wrong metric | 422 | in-process + driver agent battery |
| malformed numeric signal | 422 | in-process + driver agent battery |
| **contradictory operator `<`** | 422 | **in-process (new §47 test, CI green)** + driver |
| proposal hash mutation | integrity failure | in-process (9-field driver probes) |
| stale approval | 409, no side effects | driver (real TTL `REMEDIATION_PROPOSAL_TTL_SECONDS`) — not run |
| foreign target | target revalidation failure | request-level spoof attempts ignored (driver); full revalidation-failure state unreachable externally without a second authoritative run — recorded honestly as partial |
| active lease competition | no double execution | driver race + remote oracle — not run |
| duplicate execution | reconcile/idempotent | driver — not run |
| remote branch moved | conflict/fail closed | driver (force-moved remote, expects 409, asserts no overwrite) — not run |
| sandbox unavailable | fail closed, no host fallback | driver (digest-shaped missing image, restore after) — not run |
| missing sandbox digest | configuration failure | compose `:?` interpolation — validated by `compose config` step |
| secrets found in artifacts | fail before upload | driver gate — not run |

## Security posture

- No credential was printed, committed or artifacted in this task (no
  secrets existed to leak); the workflow never echoes tokens, auto-masks
  environment secrets, and the artifact upload is gated by a recursive
  secret-pattern scan that fails the job first.
- The available all-powerful token was deliberately NOT placed in the
  `e2e-staging` environment (§57 stop condition honored).
- Sandbox host-execution fallback: unchanged (none); validation profile
  allowlist unchanged; gateway authorization, provenance and hash
  machinery untouched (diff audit: 8.4.2 touches only harness files,
  two E2E Dockerfiles, one operator assertion + one comment).

## Cleanup

Implemented as an `if: always()` step: compose `down -v`, `kind delete
cluster ares-e2e`, registry container removal, kubeconfig removal, and
run-scoped remote cleanup that refuses any branch not matching
`automation/remediation/e2e/*` (PR close + branch delete on the fixture
repository only, tolerant of failures so cleanup never masks the test
result). Not exercised (no run).

## Local/CI regression evidence (executed)

- platform `pytest tests/ deployment_service/tests`: **325 passed + 131
  subtests** (incl. 24 new harness-helper tests)
- incident 35-module unittest scope: **559 OK (3 skipped)**
- gateway `pytest api_gateway/tests`: **79 passed + 60 subtests**
- backend `pytest tests/`: **49 passed**
- `compileall` incident/gateway/deployment/agent/e2e: OK; `git diff
  --check`: clean; workflow static checks: OK (above)

## Remaining blockers (exact, actionable)

1. **Fixture repository** `gm-prog/ares-e2e-fixture` must be created
   (private) with seed commit containing
   `src/service_config.py` = `SERVICE_NAME = "checkout-service"` —
   requires a credential with repo-create rights (not the App token).
2. **Restricted fixture token**: a fine-grained PAT or GitHub App
   installation token scoped to *that repository only* (contents+PRs
   write) must be minted in GitHub settings — it must NOT be able to
   modify `gm-prog/Autonomous-Devops-Engineer`.
3. **Protected environment**: create `e2e-staging` with required
   reviewers; add secrets `E2E_JWT_SECRET` (random ≥32 bytes) and
   `E2E_FIXTURE_GITHUB_TOKEN` (the restricted token); set dispatch
   input `fixture_seed_sha` to the immutable seed commit.
4. **Default-branch availability**: merge
   `.github/workflows/e2e-golden-path.yml` to `main` (owner action;
   this session may not touch `main`) — `workflow_dispatch` only works
   from the default branch.
5. Local execution remains impossible by design (no container runtime /
   registries in this sandbox) — the runner is the only venue.

### Exact manual dispatch procedure (§53)

```text
1. create gm-prog/ares-e2e-fixture (private) + seed commit (content above)
2. mint fixture-scoped token; create environment e2e-staging with
   required reviewers; add secrets E2E_JWT_SECRET, E2E_FIXTURE_GITHUB_TOKEN
3. merge .github/workflows/e2e-golden-path.yml to main (PR or direct)
4. gh workflow run e2e-golden-path.yml -f fixture_seed_sha=<seed-40hex>
5. approve the e2e-staging environment request
6. one run id → one artifact bundle → one e2e-manifest.json
```

## §56 final hostile audit (answered with evidence)

- main exactly `7b30a56d…`? **YES** (re-verified after push) · six
  integration refs untouched? **YES** (6 audited / 0 modified,
  verified byte-identical) · PRs
  untouched? **YES** · force-push? **NONE** · unrelated files modified?
  **NO** (diff confined to harness/E2E files + §47 assertion).
- Did the real compose stack boot / readiness pass / kind run /
  deployment-service reach kind / terraform execute / DEPLOYED reached?
  **NO — not run (NOT VERIFIED)**.
- Did monitoring publish / worker create incident / evidence come from
  deployment-service / RCA cross HTTP / proposal use real service /
  repo+SHA from authoritative evidence? **NO — not run**; in-process
  analogues are CI-green and labelled as such, never as staging proof.
- Real sandbox ran / digest-pinned / fixture assertion exact / real
  commit / remote branch / real PR / remote file patched? **NO — not
  run** (all implemented as assertions).
- Unauthorized access fails / tampering fails closed / duplicate
  reconciles / lease honored / stale fails early / remote tamper fails
  closed / sandbox failure avoids host execution / artifacts secret-free?
  **Unit-level YES (CI evidence); external NOT VERIFIED.**
- Any "unknown"? The five blockers above are the complete known set.

## Vocabulary discipline

Harness code and this report use only IMPLEMENTED / TESTED LOCALLY /
TESTED IN CI / PASS / PARTIAL / FAIL / BLOCKED / NOT VERIFIED. No claim
of production-readiness, full autonomy, exactly-once semantics,
cryptographic source-to-artifact derivation, or staging success is made.
The execution model remains at-least-once attempts + deterministic
idempotency + durable lease + CAS + reconciliation + fail-closed
conflicts.

---

# Phase 8.4.2-C corrective hardening (2026-10-06)

## Executive result

```text
HARNESS: CORRECTIVE REPAIRS IMPLEMENTED + CI-VALIDATED (per-defect below)
LIVE E2E: NOT VERIFIED — the golden path has still never executed
          end-to-end on GitHub Actions (workflow not on the default
          branch; fixture repo/secrets not provisionable from this
          session's credential). No stage in this document is promoted
          to PASS on the basis of the corrective work.
```

Authoritative base of this phase: `f518a171…` (Phase 8.4.1 head);
start point: previous head `75943a743eef15a5b7c42cd6862cffe27750dd0e`.
`main` stays `7b30a56d2bfd06798c0a90023acd1c6bd5cd3420` — untouched.

## Happy-path chain as now implemented (audit narrative)

1. Dispatch-only workflow (`e2e-golden-path`, `permissions: contents: read`,
   `environment: e2e-staging`) validates slug/SHA inputs and the presence
   of the two step-scoped secrets.
2. Pinned toolchain installs (terraform/kubectl checksum-verified, kind
   via sumdb-verified module install).
3. Compose config validation runs with valid-format digest placeholders.
4. **Load immutable image pins** (renamed and reworked in 8.4.2-D):
   committed `e2e/pinned-images.txt` digests are parsed fail-closed,
   turned into `repository@sha256:<64hex>`, pulled and inspected by that
   exact reference, then exported/recorded — no tag is ever resolved at
   dispatch time and the workflow text contains no image tag.
5. **Registry ordering (P0-1)**: registry container starts on its own
   `e2e-registry-net` first; kind is created after it; only then is the
   registry connected to the `kind` network, TCP reachability is proven
   from the node, and (after publishing) a fixture pod proves a real
   image pull from the registry.
6. Application/sandbox/workload images build from digest-pinned bases
   (`ARG BASE_IMAGE` + `FROM ${BASE_IMAGE:?…}` fail-closed).
7. Workspace root step creates the ONE host-visible directory
   `/tmp/ares-e2e-workspaces` (job env `E2E_WORKSPACES_ROOT`).
8. Compose boots with step-scoped real secrets; readiness uses bounded
   observable probes; deployment-service reaches kind by container name.
9. Live §6 proof: a file written inside the platform's remediation
   workspace is found at the identical path on the runner host and is
   readable READ-ONLY at `/workspace` inside the real sandbox image
   (single `:ro` bind, network none, no write possible).
10. Live §7 proof: unauthenticated `git ls-remote` against the fixture
    repo is denied; an authenticated fetch succeeds with the token fed
    on stdin into `GIT_CONFIG_*` env (never argv/URL/config/logs).
11. The driver executes the full gateway-only chain (preflight →
    security → deployment → monitoring → replay → evidence → RCA →
    proposal → approval → sandbox-failure → execution → remote checks →
    DB cross-check → finalize), writing the manifest and artifacts.
12. Evidence collection → recursive secret-scan backstop (gates upload)
    → artifact upload → teardown (compose, kind, registry, workspace
    root, fixture-only branch/PR cleanup).

## Defect-by-defect results

| ID | Defect | Fix | Evidence |
| --- | --- | --- | --- |
| P0-1 | Registry started `--network kind` (assumed kind network pre-existed); no proofs | Registry now created first on `e2e-registry-net`, connected after `kind create`, TCP + pull proofs recorded (`registry-state.txt`, `registry-networks-preconnect/postconnect.txt`, `kind-registry-connectivity.txt`, `kind-image-pull-proof.txt`, `workload-push.txt`) | `TestRegistryOrderingRegression` (6 tests, ordering asserted inside the step block); live NOT VERIFIED |
| P0-2 | No dedicated host-visible workspace root; sandbox would bind-create an absent dir | Job env `E2E_WORKSPACES_ROOT`; compose mounts `/tmp/ares-e2e-workspaces` at the same path host+container; `RemediationWorkspaceService(workspace_root=…)` requires absolute+existing root, mkdtemp under it, cleanup refuses outside; `build_run_plan` (root mode) requires mount source to exist beneath `REMEDIATION_WORKSPACE_ROOT` and fails closed; §6 live visibility/RO proof step added | `TestHostVisibleWorkspace` (7 tests); existing sandbox suites (559-module CI set) unmodified and green |
| P0-3 | Fixture acquisition unauthenticated/prefix-cleanup mismatch | Root-mode `prepare()` fails closed without `GITHUB_OAUTH_TOKEN`; clone+fetch carry the token via per-process `GIT_CONFIG_*` `http.extraHeader`; URL/argv never contain credentials; workflow proves private-then-authenticated fetch via stdin pipe | `TestAuthenticatedFixtureClone` (6 tests) + live workflow proof (NOT VERIFIED) |
| P1-4 | Weak race oracle (`successes >= 0`), no order guarantees | `classify_execution_outcomes()` requires exactly two outcomes, exactly one winner ∈ {200,502,504} and exactly one 409, zero invalid; driver assertion strict; **[200,502,504] winner semantics = relay-timeout-with-continuation** (gateway 10 s relay while durable execution proceeds; verified via read endpoints/DB/remote, never via the timed-out response) | `TestConcurrencyOracle`: PASS `[200,409] [409,200] [502,409] [409,502] [504,409] [409,504]`; FAIL `[200,200] [502,502] [504,504] [409,409] [200,500] [404,409] [] [200] [200,409,409]` |
| P1-5 | Floating build inputs (`python:3.11-slim` bare in workflow/Dockerfiles; bare `resolve <tag>` step) | `pinned-images.txt` (source, pin, env key); Dockerfiles/compose use `ARG/…:?` fail-closed refs; static tests reject `python:3.11-slim`/`python:latest`/`python@invalid` in workflow+compose+Dockerfiles and require `@sha256:<64hex>` everywhere. **PARTIAL — superseded by Phase 8.4.2-D:** this 8.4.2-C step still resolved `UNRESOLVED` pins from mutable tags at dispatch time, which is not immutability. The pin file now carries committed digests and the workflow performs no tag resolution (see “Phase 8.4.2-D corrective closure” below) | `TestImmutability` (8 tests) + 8.4.2-D `TestCommittedImmutablePins`/`TestWorkflowProvenanceWiring`; sandbox digest enforcement untouched |
| P1-6 | Secrets job-global; `compose config` rendered live secrets into artifacts; upload unconditional | Secrets moved to step `env:` (validate/boot/prove/execute/driver/cleanup only); diagnostics rendered by `render_compose_config()` from a sanitized env (placeholder `[REDACTED-NON-SECRET]`, which the scanner now explicitly exempts while still matching real values); recursive scan is a separate step with `id: secretscan`; upload `if: … && steps.secretscan.outcome == 'success'` | `TestSecretStaging` (8 tests incl. injected-fixture-secret fails scan → upload gated) |
| 7 | Replay used fixed `time.sleep(6)` as proof | Bounded `wait_until("replay-consumed", …)` over observable state: group `last-delivered-id` ≥ replayed id AND `XPENDING` empty for that id; deadline+interval+structured timeout diagnostics; no `time.sleep` anywhere in the replay path | `TestReplayPolling` (3 tests) |
| 8 | Docs under-counted the integration refs (five-refs phrasing) | Six integration refs listed — **6 audited / 0 modified**: `4bd799b3`, `3d87007d`, `71713d83`, `a0bf7600`, `1184eb67`, `d1961e43` | `test_docs_list_six_integration_refs` |
| 9 | `cancel-in-progress` wording overstated | Workflow header + this report state: `cancel-in-progress: false` only prevents cancellation of a running execution; **no stronger queue guarantee is claimed** than GitHub documents (no FIFO/strict-ordering claim for the queued run) | `test_workflow_comments_state_no_stronger_queue_guarantee`, `test_docs_state_cancel_in_progress_scope_honestly` |

Driver contract fixes found during the audit and included above:
`_fixture_prs()` now queries the **recorded** `branch_name`
(`automation/remediation/{incident}/{proposal}` via
`RemediationWorkspaceService.build_branch_name`), the sandbox-failure
check queries ALL fixture PRs (`state=all`, no head filter), the
manifest gained scalar fields `workspace_root`, `fixture_seed_sha`,
`registry_image_digest`, `kind_node_image_digest`, `base_images`,
`built_image_digests` (all validated against `^[a-z_]+$` scalars), and
preflight fails closed on fixture slug/seed/token/JWT/sandbox digest/
workspaces-root (`E2E_WORKSPACES_ROOT missing or not absolute`).

## §13 repository-wide credential-flow audit

Scripted term search over all tracked `.py/.yml/.md/.sh/.txt/.json`
files (terms: `ghp_`, `github_pat_`, `gho_`, `ghu_`, `ghs_`, `ghr_`,
`x-access-token`, `Bearer `, `GIT_CONFIG_VALUE_0`, `extraHeader`,
`GITHUB_OAUTH_TOKEN`, `E2E_FIXTURE_GITHUB_TOKEN`, `E2E_JWT_SECRET`,
`JWT_SECRET`, `password=`, `Authorization:`), every match classified by
inspecting the flow:

- **secure flows**: `GIT_CONFIG_VALUE_0`/`extraHeader` matches are all
  the env-only credential mechanism (workspace service, push tests,
  workflow stdin pipe, corrective tests); `Bearer ` in gateway auth is
  the documented authorization header parsing; `x-access-token` matches
  exist only as deny-patterns in scanner/test code (never constructed).
- **unit tests / deny-patterns**: `ghp_`-shaped literals appear only in
  test fixtures and in `proposal_execution_service.py`'s rejection
  regex (a pattern that BLOCKS tokens, not one that emits them); the
  single synthetic `ghp_…` in `tests/test_e2e_corrective.py` is
  deliberately under GitHub's real token length.
- **redacted/legacy docs**: `FORENSIC_REPORT.md` (pre-existing tracked
  file), `CHANGELOG.md`, `README.md`, roadmaps mention token/secret
  NAMES only; no values.
- **forbidden**: **0 matches** — no literal credential exists in the
  repository, no token in any URL/`.git-config`/argv/log/artifact path
  (`test_no_static_secret_values`, `test_no_token_in_command_lines…`,
  workspace-service argv assertions).
- Result: **PASS (static audit)**; live artifact contents remain
  NOT VERIFIED until a run uploads them.

## §14 sandbox boundary re-verification

Verified by executable tests (`TestHostVisibleWorkspace`) plus the
unmodified CI sandbox suites: exactly ONE mount expression
`{workspace}:/workspace:ro` (asserted `== 1` in source); absolute-path
requirement; root-mode existence + beneath-root enforcement (fail
closed, no other host path); `docker.sock` string absent from both
sandbox modules (the socket is mounted only on `incident-service`, the
orchestrator, per the Phase 6.2.2 design); `--network none`, read-only
rootfs, tmpfs `/tmp`, cap-drop ALL, no-new-privileges, pids/memory/cpu
limits and non-root default unchanged; no host/in-process fallback
(`remediation validation will not run on the host` guard intact).
**PASS (static/unit)**; container-execution claims NOT VERIFIED
locally (no Docker runtime in this environment).

## §15 production-boundary audit (intentional production-path changes)

| Path | Change | Reason | Tests |
| --- | --- | --- | --- |
| `incident_service/…/remediation_workspace_service.py` | Constructor `workspace_root` param (default ← `REMEDIATION_WORKSPACE_ROOT` env, else legacy system-tmp); root-mode clones authenticate + clean only under root | P0-2/P0-3; production default (env unset) byte-equivalent to previous behaviour | corrective tests + existing workspace-service suite (signature update `fake_git(…, **kwargs)` only) |
| `incident_service/…/validation_sandbox.py` | Root-mode guard: mount source must exist and lie beneath `REMEDIATION_WORKSPACE_ROOT` | P0-2 fail-closed; guard inactive when env unset (unit contexts) | corrective + existing sandbox suites (35-module set) |
| `deployment_service/Dockerfile.e2e`, `incident_service/Dockerfile.e2e` (8.4.2-C) — **extended in 8.4.2-D** to the full E2E build surface: `api_gateway/`, `repo_service/`, `agent_service/`, `monitoring_service/Dockerfile.e2e` + `e2e/workload/Dockerfile` | `ARG BASE_IMAGE` + fail-closed `FROM` | P1-5 immutability (E2E-only Dockerfiles; production Dockerfiles untouched and never built by the E2E workflow) | `TestImmutability`, `TestE2EBuildSurfaces` |
| `e2e/*`, workflow, `docker-compose.e2e.yml` | harness-only | scope | test files below |

No other production file changed; `main`, integration refs and PRs
#8–#11 untouched.

## §16 test matrix (executed this phase, exact cwd + counts)

| Scope (cwd) | Command | Result |
| --- | --- | --- |
| `devops-ai-platform` | `pytest tests/ deployment_service/tests` (CI scope) | **403 passed + 131 subtests** (325 baseline + 78 new corrective) |
| `devops-ai-platform` | CI incident job command (`python -m unittest` with the 35 enumerated modules) | **Ran 559 — OK (3 skipped)** |
| `devops-ai-platform` | `python -m unittest discover -s incident_service -p 'test_*.py' -t .` (superset) | Ran 553 — OK (3 skipped) |
| `devops-ai-platform` | `compileall incident_service api_gateway` + `pytest api_gateway/tests` (CI scope) | **79 passed + 60 subtests** |
| `backend` | `pytest tests/` (CI scope) | **49 passed** |
| `devops-ai-platform` | `pytest tests/test_e2e_harness.py` | **24 passed + 7 subtests** (unmodified) |
| repo root | `git diff --check` | clean |

## §17 workflow static validation (executed)

Real YAML parse (`yaml.safe_load`) → OK; `bash -n` on every `run:`
block → OK (0 failures); both actions pinned to full SHAs
(`actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1`,
`actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a`);
`on: workflow_dispatch` only, no `pull_request`/`pull_request_target`
keys; `permissions: contents: read`; `environment: e2e-staging`; job
env contains **zero** `secrets.*` references; every secret-touching
step declares its own `env:`; no static secret-shaped values; step
order has no forward dependencies (asserted). actionlint remains
unavailable in this environment (download blocked) — GitHub validates
the workflow on push.

## §18 CI scopes (exact commands, cwd, counts)

Identical to §16 table; no aggregate "grand total" is claimed. Local
environment cannot run docker/kind/terraform → **§19: no local
golden-path claim is made; LIVE E2E: NOT VERIFIED.**

## §20 workflow step order (no forward dependencies)

validate inputs → toolchain → compose config validation → load
immutable image pins (+ external provenance exports) →
registry/kind/connect/prove → build immutable images (+ built-image
provenance exports) →
publish + kind pull proof → create workspace root → boot + readiness →
§6 workspace proof → §7 git-auth proof → driver → collect → scan gate
→ upload (gated on scan) → cleanup (compose/kind/registry/workspace
root + fixture-only remote branch cleanup).

## §21 driver fail-closed preconditions (asserted in `preflight()`)

fixture slug (`E2E_FIXTURE_REPOSITORY is not owner/repo`), seed
(`E2E_FIXTURE_SEED_SHA is not 40-hex` + live commit + seed content
exact match), token presence (`E2E_FIXTURE_GITHUB_TOKEN missing`),
JWT (`E2E_JWT_SECRET missing`), sandbox digest
(`REMEDIATION_SANDBOX_IMAGE is not digest-pinned`), workspaces root
(`E2E_WORKSPACES_ROOT missing or not absolute` / `… does not exist on
the runner`); seed `SERVICE_NAME = "checkout-service"`; target
`checkout-service-remediated` comes only from the runner's code
constant (fixture config cannot alter it — asserted).

## §24 manifest fields

`schema`, `result`, `workflow_run_id`, `source_repository`,
`source_sha`, `fixture_seed_sha`, `fixture_repository`,
`remediation_branch`, `workspace_root`, `registry_image_digest`,
`kind_node_image_digest`, `base_images`, `built_image_digests`,
`sandbox_image_digest`, `terraform/kubectl/kind versions`, evidence
IDs, stage results — all **scalars** (`validate_manifest` enforces
`^[a-z_]+$` keys, non-container values); no secret can enter (scanner
+ shape validation). 8.4.2-D adds the optional `provenance_rejection`
field and the live-execution completeness gate
(`finalize_execution_manifest`): a PASS is impossible while any of the
eight required provenance fields is empty.

## §28 hostile audit (explicit answers)

1. **Registry** — does anything assume the kind network pre-exists?
   **No**: registry runs on `e2e-registry-net` before `kind create`;
   the kind attach is a separate later command; ordering + proofs are
   regression-tested.
2. **Workspace** — one root? fail-closed if absent? cleanup escaped?
   **One root** (`E2E_WORKSPACES_ROOT`, compose-mounted at the identical
   path), absent root/mount source fails closed, `_cleanup_path`
   refuses anything outside the root (test raises), no host fallback.
3. **Git auth** — token in URL/config/argv/logs/artifacts? **No**:
   stdin→env `GIT_CONFIG_*` only; tests assert token absence from argv,
   URLs, `.git/config` and workflow command lines; live proof step
   (NOT VERIFIED).
4. **Concurrency** — does the oracle accept two winners/zero winners?
   **No**: exactly-one-winner + exactly-one-409 + terminal `PR_CREATED`
   or FAIL (15 patterns asserted).
5. **Immutability** — any floating tag left? **None** in
   workflow/compose/Dockerfiles (static tests). 8.4.2-C still resolved
   `UNRESOLVED` pins from mutable tags at dispatch; **8.4.2-D replaced
   that with committed digests** (no resolution path remains). Sandbox
   digest enforcement untouched.
6. **Secrets** — can a secret enter artifact staging? **Not via the
   primary path** (sanitized render; scanner exemption is limited to
   the literal placeholder) and the backstop scan **gates upload**
   (injected-secret test proves `if:` gating).
7. **Cleanup** — can it touch production or escape the root?
   Refuses any branch outside `automation/remediation/`, refuses the
   production repo explicitly, workspace rm is root-scoped, kind/
   registry deletion is name-scoped.

## Remaining blockers (unchanged honesty)

1. Golden-path workflow is not on the default branch → no dispatch
   run exists (**LIVE E2E: NOT VERIFIED**).
2. This session's GitHub credential cannot create the fixture repo or
   provision `E2E_JWT_SECRET`/`E2E_FIXTURE_GITHUB_TOKEN` (App token,
   `Resource not accessible by integration`); §57 stop honored — the
   all-powerful token was NOT wired.
3. No Docker/kind/terraform locally → all container proofs above are
   static/unit-level until CI executes them.

## Vocabulary discipline (this section)

PASS is used only for checks that actually executed (tests, static
audits). Everything requiring GitHub/Docker/kind execution is NOT
VERIFIED. No production-readiness, exactly-once, or staging-success
claim is made.

## Corrective-hardening CI evidence (head `8bbee504a8688f51146a565123b480da59d7b50f`)

Commits: `be19a4e` (fix(e2e)) → `3c729cb` (docs(e2e)) → `8bbee50`
(test(e2e)); pushed to `arena/01a0cf63-autonomous-devops-engineer` only.

- push run `37457087915` — **success, 5/5 jobs** (API gateway checks
  `112247232467`, Compose validation `112247232663`, Backend tests
  `112247232818`, Platform smoke tests `112247232825`, Incident, RCA
  and remediation checks `112247232880`).
- pull_request run `37457092501` — **success, 5/5 jobs**
  (`112247247671`, `112247247896`, `112247247929`, `112247248040`,
  `112247248238`).

LIVE E2E: NOT VERIFIED — these runs execute the CI suites only; the
golden-path workflow remains dispatch-only and not on the default
branch, so no golden-path execution exists.

---

# Phase 8.4.2-D corrective closure — provenance & manifest auditability (2026-10-06)

## Executive result

```text
HARNESS: CORRECTIVE REPAIRS IMPLEMENTED + CI-VALIDATED (per-defect below)
LIVE E2E: NOT VERIFIED — the golden path has still never executed
          end-to-end on GitHub Actions. No run of the workflow
          "E2E Golden Path (staging)" exists; nothing in this section
          is promoted to PASS on the basis of static, unit or ordinary
          CI evidence.
```

Scope: the two P1 defects left open by the independent audit of Phase
8.4.2-C (image immutability resolved at dispatch time; manifest
provenance fields structurally present but never populated), the §6.2
E2E/production Dockerfile boundary, and the P2 credential-hygiene and
wording corrections. Phase 8.4.2-C behaviour is otherwise preserved.

| Item | Value |
| --- | --- |
| Phase 8.4.2-C head (base of this phase) | `b3697348dc1af59fe70fa167359c305579f2c7ec` |
| `main` | `7b30a56d2bfd06798c0a90023acd1c6bd5cd3420` — **UNCHANGED** (re-verified via `git ls-remote`) |
| Integration refs | **six**, 6 audited / 0 modified, byte-identical: `4bd799b3bb1404d713a00ae12ca4f43de6287e6d` (control-plane-foundation-v1), `3d87007db82f4ca11f207462986d4d54c74cce3d` (phase-8-control-plane-v1), `71713d83b6992a8ec70df00807d7db26759e6669` (phase-8.1-v1), `a0bf7600a25f2821fc61a8fcf3fba9c408667826` (phase-8.2-v1), `1184eb677c6e53178c42fd7c8c1331efd61d00b3` (remediation-platform-reconciliation), `d1961e43ba21725daaaf4f294b369f72c0946fb6` (remediation-reconstruction) |
| PRs #8–#11 | untouched |
| Force-push / history rewrite / rebase | none |

## P1-5 closure — image provenance is now committed, not resolved

**Before:** `e2e/pinned-images.txt` carried `UNRESOLVED` in the pin
column and the workflow resolved those entries with `docker pull <tag>`
+ `RepoDigests` **at dispatch time**. A moved registry tag changed the
build input of an unchanged commit.

**After:** the pin column carries the immutable digest itself. The
committed grammar is `<source-name:tag> sha256:<64hex> <ENV_KEY>`; the
tag is provenance only (where the digest was observed), the digest is
the identity that is pulled.

| Source (observed tag) | Committed digest | Exported key |
| --- | --- | --- |
| `python:3.11-slim` | `sha256:0dd364ba7e10242f07755449e3a3d0e35f9efd987952737b90def6709ab0c5ce` | `E2E_PYTHON_BASE_IMAGE` |
| `postgres:15-alpine` | `sha256:f7d23353e1b15400d22ebe31189f4d314b87a4c129cc400c8c2d8d4ca127bf81` | `E2E_POSTGRES_IMAGE` |
| `redis:7-alpine` | `sha256:858f009f9709ce576febc734aa78b8f6d624b82571f9ddb6bda4377c833b3499` | `E2E_REDIS_IMAGE` |
| `qdrant/qdrant:v1.12.4` | `sha256:241edb9d7778327516ef218f8c74e1bd61b5ea42cd4f193cb8d0896199705636` | `E2E_QDRANT_IMAGE` |
| `registry:2` | `sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373` | `REGISTRY_IMAGE` |
| `kindest/node:v1.31.4` | `sha256:2cb39f7295fe7eafee0842b1052a599a4fb0f8bcf3f83d96c7f4864c357c6c30` | `NODE_IMAGE` |

**Digest authority (no digest is invented).** Every value was read on
2026-10-06 from the registry's own API — `hub.docker.com/v2/repositories/
library/{python,postgres,redis,registry}/tags/<tag>` and
`/v2/repositories/{qdrant/qdrant,kindest/node}/tags/<tag>` — and taken
verbatim from the manifest-index `digest` field. `kindest/node:v1.31.4`
agrees with a second authoritative source, the kubernetes-sigs/kind
**v0.26.0** release notes (`kindest/node:v1.31.4@sha256:2cb39f72…`).
The canonical pin file is `devops-ai-platform/e2e/pinned-images.txt`;
the per-run evidence copy is `e2e-artifacts/image-provenance-inputs.txt`.

**Workflow contract (step “Load immutable image pins (committed
digests, §5)”, before registry/kind/build):**

```text
committed pin → strict parse (e2e.image_pins / helpers.parse_pinned_images)
              → repository@sha256:<64hex>
              → docker pull <that exact ref>
              → docker image inspect <that exact ref> and require the
                daemon's RepoDigests to contain it verbatim
              → export KEY=ref to $GITHUB_ENV + record it as evidence
```

No sentinel, no tag lookup, no compatibility mode: a missing, malformed,
duplicated or non-digest pin aborts the job with exit 1 and empty
stdout. `UNRESOLVED` no longer exists anywhere in the workflow, the pin
file or the pin parser, and the workflow text still contains no image
tag at all. The sandbox contract is untouched (`--pull never`,
`name@sha256:<64hex>`, `--network none`, read-only rootfs, non-root,
`cap-drop ALL`, `no-new-privileges`, exactly one `:ro` workspace bind).

## E2E Dockerfile scope (§6.2) — corrected wording

The earlier “two Dockerfiles” phrasing was wrong. The golden-path
`docker compose build` builds **seven** services, so seven E2E-specific
build surfaces are digest-controlled (`ARG BASE_IMAGE` +
`FROM ${BASE_IMAGE:?…}`), plus the separately built workload image:

```text
E2E-specific Dockerfiles covered by the golden-path build:
- devops-ai-platform/api_gateway/Dockerfile.e2e          (new, 8.4.2-D)
- devops-ai-platform/repo_service/Dockerfile.e2e         (new, 8.4.2-D)
- devops-ai-platform/agent_service/Dockerfile.e2e        (new, 8.4.2-D)
- devops-ai-platform/monitoring_service/Dockerfile.e2e   (new, 8.4.2-D)
- devops-ai-platform/deployment_service/Dockerfile.e2e   (8.4.2-C)
- devops-ai-platform/incident_service/Dockerfile.e2e     (8.4.2-C; now
  also used by the incident-event-worker build surface)
- devops-ai-platform/e2e/workload/Dockerfile             (8.4.2-C)
```

Production Dockerfiles (`api_gateway/`, `repo_service/`,
`agent_service/`, `deployment_service/`, `monitoring_service/`,
`incident_service/Dockerfile`) **remain tag-based by design** and are
**never built by the E2E workflow** — `TestE2EBuildSurfaces` asserts
both halves: every compose service with a `build:` section maps to an
`.e2e` Dockerfile, and no production Dockerfile path is referenced by
the E2E stack. The claim “all E2E build inputs are digest-addressed” is
therefore now true of the actual build set, not of a subset.

## P1 manifest provenance closure — how each field is populated

All four values are generated from workflow/runtime state and exported
to `$GITHUB_ENV` **before** the “Execute golden path driver” step; the
driver reads them in `Harness.__init__` and writes them into
`e2e-manifest.json`. Nothing is patched into the manifest afterwards,
and no value in the manifest is transcribed from this document.

| Manifest field | Source | Exported by |
| --- | --- | --- |
| `registry_image_digest` | the committed `REGISTRY_IMAGE` pin — the exact ref passed to `docker run … "${REGISTRY_IMAGE}"` | pins step (`E2E_REGISTRY_DIGEST`) |
| `kind_node_image_digest` | the committed `NODE_IMAGE` pin — the exact ref passed to `kind create cluster --image "$NODE_IMAGE"` | pins step (`E2E_KIND_NODE_DIGEST`) |
| `base_images` | deterministic scalar `KEY=ref;KEY=ref` (keys sorted, no trailing separator) over the four base/service pins | pins step (`E2E_BASE_IMAGES`) |
| `built_image_digests` | real post-push `docker inspect … {{index .RepoDigests 0}}` of the workload and sandbox images, shape-verified before export | build step (`E2E_BUILT_IMAGE_DIGESTS`) |
| `sandbox_image_digest` | same post-push inspection (`E2E_SANDBOX_DIGEST`) | build step |
| `source_sha`, `fixture_seed_sha`, `workspace_root` | job env / dispatch input | job env |

Scalar encoding is `helpers.format_scalar_mapping` (inverse:
`parse_scalar_mapping`), so the manifest stays scalar-only while
remaining machine-readable:

```text
E2E_BASE_IMAGES=E2E_POSTGRES_IMAGE=postgres@sha256:…;E2E_PYTHON_BASE_IMAGE=python@sha256:…;E2E_QDRANT_IMAGE=qdrant/qdrant@sha256:…;E2E_REDIS_IMAGE=redis@sha256:…
E2E_BUILT_IMAGE_DIGESTS=E2E_WORKLOAD_IMAGE=localhost:5001/ares-e2e-workload@sha256:…;REMEDIATION_SANDBOX_IMAGE=localhost:5001/ares-e2e-sandbox@sha256:…
```

**Fail-closed gates.** (1) The pins step re-reads `$GITHUB_ENV` and
aborts unless `E2E_REGISTRY_DIGEST`, `E2E_KIND_NODE_DIGEST` and
`E2E_BASE_IMAGES` are present and non-empty. (2) The build step verifies
both built refs match `@sha256:<64hex>` and aborts unless all four
provenance variables are exported. (3) `helpers.finalize_execution_
manifest()` refuses to let a live run claim PASS while any of
`source_sha`, `fixture_seed_sha`, `workspace_root`,
`registry_image_digest`, `kind_node_image_digest`, `base_images`,
`built_image_digests`, `sandbox_image_digest` is empty: the result is
downgraded to **FAIL** with a `provenance_rejection` field, and the
driver's exit code follows the manifest. Schema validity and live
provenance completeness stay separate — preflight/local
`NOT_VERIFIED`/`BLOCKED` manifests remain structurally representable via
`finalize_manifest`.

**Evidence bundle additions** (image names, digests and version strings
only — never credential material; the recursive secret scan still gates
upload): `image-provenance-inputs.txt`, `image-provenance-built.txt`,
`manifest-provenance-env.txt`, alongside the existing
`docker-inspect-digests.txt`.

## D-1 — latent defect found during this audit (fixed)

`helpers.validate_digest_ref()` rejected a registry host with a port, so
the driver's preflight would have classified the real
`localhost:5001/ares-e2e-sandbox@sha256:…` reference as “not
digest-pinned” and returned BLOCKED on a live run. The regex now accepts
an optional `host[:port]/` prefix while still rejecting tags and short/
upper-case digests. `validation_sandbox.py`'s own
`^[^@\s]+@sha256:[0-9a-f]{64}$` guard already accepted the form and is
unchanged — the sandbox boundary is not relaxed.

## P2 — raw Git credential no longer inherited by child processes

`RemediationWorkspaceService._run_git()` now strips `GITHUB_OAUTH_TOKEN`
from **every** child environment. Authentication is supplied per call as
`GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_0`/`GIT_CONFIG_VALUE_0`
(`http.extraHeader: Authorization: Bearer …`) only for the commands that
need the remote (clone/fetch/ls-remote/push); `checkout`, `rev-parse`
and `switch` run with no token material at all. The token never appears
in argv, clone/remote URLs, `.git/config`, logs, exceptions or
artifacts. `TestCredentialHygiene` captures the real child environment
for both cases and adds a live `git config` process proof.

## §16 deterministic provenance audit (no Docker, no GitHub)

`pytest devops-ai-platform/tests/test_e2e_corrective.py -k ProvenanceAudit`
runs nine checks: (1) zero `UNRESOLVED` entries, (2) every pin is
`sha256:<64hex>`, (3) every key valid and expected, (4) no mutable-tag
resolution path in the workflow, (5) all four provenance variables
exported, (6) exports precede driver execution, (7) the driver maps all
four into the manifest, (8) successful finalization rejects missing
provenance, (9) this document does not claim a live E2E PASS.

## Test matrix executed for this phase (exact commands)

| Scope (cwd) | Command | Result |
| --- | --- | --- |
| `devops-ai-platform` | `pytest tests/test_e2e_corrective.py` | **138 passed** (78 kept + 60 new) |
| `devops-ai-platform` | `pytest tests/test_e2e_harness.py` | **31 passed + 18 subtests** |
| `devops-ai-platform` | `pytest tests/ deployment_service/tests` (CI scope) | **470 passed + 142 subtests** |
| `devops-ai-platform` | CI incident job (`python -m unittest`, 35 modules) | **Ran 559 — OK (3 skipped)** |
| `devops-ai-platform` | `compileall` + `pytest api_gateway/tests` (CI scope) | **79 passed + 60 subtests** |
| `backend` | `pytest tests/` (CI scope) | **49 passed** |
| repo root | `git diff --check` | clean |
| repo root | workflow `yaml.safe_load` + `bash -n` on all 17 `run:` blocks | OK / 0 failures |

Regression strength was verified by mutation: with the pre-patch
workflow, pin file, driver and workspace service restored, **27 of the
new tests fail** (sentinel accepted, exports missing, built digests
tag-derived, token inherited, all nine audit points) and they pass only
against the corrected implementation.

## CI evidence discipline

The CI runs cited in the Phase 8.4.2-C section (`37457087915`,
`37457092501`, `37457291288`, `37457298129`) are **ordinary `ci.yml`
runs** — backend tests, platform smoke tests, API gateway checks,
incident/RCA/remediation checks, compose validation. They are *not*
golden-path executions and are not relabelled as such. `ci.yml` does not
contain the golden-path job; `e2e-golden-path.yml` is `workflow_dispatch`
only and is not on the default branch, so ordinary CI being green says
nothing about the golden path having run.

## Hostile audit answers (Phase 8.4.2-D)

1. Can the same commit produce a different E2E base image tomorrow
   because a tag moved? **No** — the digest is committed; the workflow
   pulls `repository@sha256:…` and verifies the daemon's RepoDigest.
2. Can `UNRESOLVED` still trigger tag resolution? **No** — the token
   does not exist in the repository surface and the parser rejects any
   non-digest pin.
3. Can `registry_image_digest` be empty after a successful live run?
   **No** — exported from the committed pin in the pins step, asserted
   non-empty there, and a PASS with it empty is downgraded to FAIL.
4. Can `kind_node_image_digest` be empty after a successful live run?
   **No** — same mechanism (`NODE_IMAGE` pin → `E2E_KIND_NODE_DIGEST`).
5. Can the manifest carry only mutable tags for the dynamic workload/
   sandbox images? **No** — their values come from post-push
   `RepoDigests` and are shape-verified before export.
6. Are provenance values derived from actual execution rather than
   hand-written docs? **Yes** — `$GITHUB_ENV` ← workflow/runtime state →
   driver → manifest; this document never feeds the manifest.
7. Do unit tests prove the fields can be populated without Docker or
   GitHub credentials? **Yes** — `TestManifestProvenance` reloads the
   driver with synthetic env values and asserts the manifest mapping
   offline.
8. Do tests reject `UNRESOLVED` rather than permit it? **Yes** —
   parser, CLI, pin-file and workflow checks all reject it.
9. Can the raw token leak into an unrelated Git child process? **No**,
   to the extent of the process-environment contract: `_run_git` removes
   it from every child env (captured in tests).
10. Did this patch alter `main` or the six integration refs? **No.**
11. Did this patch prove the live golden path executed? **No — LIVE
    E2E: NOT VERIFIED.**
12. Did CI go green merely because the workflow is absent from `main`?
    Ordinary CI never executes the golden path at all; its green status
    covers the five `ci.yml` jobs only, and the golden-path workflow
    remains dispatch-only and unexecuted.

## Remaining blockers (unchanged honesty)

1. The golden-path workflow is dispatch-only and not on the default
   branch → no run exists (**LIVE E2E: NOT VERIFIED**).
2. This session's GitHub credential cannot create the disposable fixture
   repository or provision `E2E_JWT_SECRET` /
   `E2E_FIXTURE_GITHUB_TOKEN` in the protected `e2e-staging`
   environment.
3. No Docker/kind/terraform in this environment → all container-level
   claims above remain static/unit-level until a real dispatch runs.
