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
  two E2E Dockerfiles, one operator assertion + one comment; Phase
  8.4.2-D later added four service-level `Dockerfile.e2e` + one worker
  override so the workflow builds **seven digest-controlled E2E
  build surfaces** total — see §6.2 table in the 8.4.2-D section
  below; production Dockerfiles remain tag-based by design and are
  never E2E-built).

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
3. Compose config validation runs with non-digest interpolation
   placeholders (never pulled, never built; real values come from the
   committed pins step).
4. **Load immutable image pins (committed digests)**: the workflow
   reads committed `e2e/pinned-images.txt`
   (`<source-name> <sha256:64hex> <env-key>`), verifies the pin
   grammar fail-closed, pulls and inspects ONLY
   `name@sha256:<64hex>`, and records each ref to
   `image-provenance-inputs.txt` + `$GITHUB_ENV` — there is **no
   dispatch-time tag resolution, no fallback, and no bare-tag pull**
   (Phase 8.4.2-D §5; the workflow text contains no bare image tags
   and no sentinel token).
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
| P1-5 | Floating build inputs (`python:3.11-slim` bare in workflow/Dockerfiles; bare `resolve <tag>` step) | **Closed in 8.4.2-D:** `pinned-images.txt` holds the six AUTHORITATIVE committed digests (`<source-name> <sha256:64hex> <env-key>`); the workflow fail-closed verifies the grammar, pulls/inspects `name@sha256:<64hex>` only, and records to `image-provenance-inputs.txt` + `$GITHUB_ENV` — no dispatch-time resolution, no fallback, no sentinel; Dockerfiles/compose use `ARG/…:?` fail-closed refs; static tests reject any non-`sha256:<64hex>` pin (sentinel/malformed/missing) and reject `python:3.11-slim`/`python:latest`/`python@invalid` in workflow+compose+Dockerfiles | `TestImmutability` (parametrized over all seven E2E Dockerfiles) + `TestProvenanceClosure` + `TestDeterministicProvenanceAudit` points 1–2; sandbox digest enforcement untouched |
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
| E2E build surfaces — `deployment_service/Dockerfile.e2e`, `incident_service/Dockerfile.e2e`, `api_gateway/Dockerfile.e2e`, `repo_service/Dockerfile.e2e`, `agent_service/Dockerfile.e2e`, `monitoring_service/Dockerfile.e2e`, `e2e/workload/Dockerfile` (seven files; the worker reuses `incident_service/Dockerfile.e2e` via compose override) | `ARG BASE_IMAGE` + fail-closed `FROM ${BASE_IMAGE:?…}` (the four service `.e2e` files added in 8.4.2-D) | P1-5 immutability + §6.2 narrowest mechanism: every surface the E2E workflow builds is E2E-specific and digest-controlled; production Dockerfiles stay tag-based by design and are never E2E-built | `TestImmutability` (parametrized over all seven) + `TestProvenanceClosure::test_e2e_build_surfaces_are_all_narrow_e2e_dockerfiles` |
| `e2e/*`, workflow, `docker-compose.e2e.yml` | harness-only | scope | test files below |

No other production file changed; `main`, integration refs and PRs
#8–#11 untouched.

## §16 test matrix (executed this phase, exact cwd + counts)

| Scope (cwd) | Command | Result |
| --- | --- | --- |
| `devops-ai-platform` | `pytest tests/ deployment_service/tests` (CI scope) | **428 passed + 131 subtests** (325 baseline + 103 corrective: the original 78 kept/updated + 25 added in 8.4.2-D incl. parametrization growth) |
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

validate inputs → toolchain → compose config validation → resolve
digests → registry/kind/connect/prove → build immutable images →
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
+ shape validation).

## §28 hostile audit (explicit answers)

1. **Registry** — does anything assume the kind network pre-exists?
   **No**: registry runs on `e2e-registry-net` before `kind create`;
   the kind attach is a separate later command; ordering + proofs are
   regression-tested.
2. **Workspace** — one root? fail-closed if absent? cleanup escaped?
   **One root** (`E2E_WORKSPACES_ROOT`, compose-mounted at the identical
   path), absent root/mount source fails closed, `_cleanup_path`
   refuses anything outside the root (test raises), no host fallback.
3. **Git auth** — token in URL/config/argv/logs/artifacts/child
   env? **No**: auth travels only via per-process `GIT_CONFIG_*`
   `http.extraHeader`; since 8.4.2-D §11 (P2) `_run_git` also scrubs
   `GITHUB_OAUTH_TOKEN` from EVERY child git environment (raw token
   never inherited); tests assert token absence from argv, URLs,
   `.git/config`, child env and workflow command lines; live proof
   step (NOT VERIFIED).
4. **Concurrency** — does the oracle accept two winners/zero winners?
   **No**: exactly-one-winner + exactly-one-409 + terminal `PR_CREATED`
   or FAIL (15 patterns asserted).
5. **Immutability** — any floating tag left? **None** in
   workflow/compose/Dockerfiles (static tests); the six inputs are
   committed SHA-256 manifest digests pulled by
   `name@sha256:<64hex>` only — **no dispatch-time resolution and no
   fallback** (8.4.2-D §5) — and recorded to
   `image-provenance-inputs.txt`; sandbox digest enforcement
   untouched.
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

# Phase 8.4.2-D — provenance & manifest auditability closure (2026-10-06)

HARNESS: CORRECTIVE REPAIRS IMPLEMENTED + CI-VALIDATED (per-item below)
LIVE E2E: NOT VERIFIED — the golden path has still never executed; the
workflow is dispatch-only and not on the default branch.

## P1-5 — immutable image pins (committed, authoritative)

`devops-ai-platform/e2e/pinned-images.txt` now carries exactly six
entries of the form `<source-name> <sha256:64hex> <env-key>`; every
pin is the authoritative tag-manifest (index) digest obtained via the
Docker Hub Hub API tag lookup (`hub.docker.com/v2/repositories/
<repo>/tags/<tag>`, top-level `digest` + `media_type`) fetched
2026-10-06; the kindest/node list digest additionally matches the
value published by the kind project. No digest was invented; none was
unavailable, so no stop condition fired.

| Source name | Committed digest | Env key |
| --- | --- | --- |
| `python:3.11-slim` | `sha256:0dd364ba7e10242f07755449e3a3d0e35f9efd987952737b90def6709ab0c5ce` | `E2E_PYTHON_BASE_IMAGE` |
| `postgres:15-alpine` | `sha256:f7d23353e1b15400d22ebe31189f4d314b87a4c129cc400c8c2d8d4ca127bf81` | `E2E_POSTGRES_IMAGE` |
| `redis:7-alpine` | `sha256:858f009f9709ce576febc734aa78b8f6d624b82571f9ddb6bda4377c833b3499` | `E2E_REDIS_IMAGE` |
| `qdrant/qdrant:v1.12.4` | `sha256:241edb9d7778327516ef218f8c74e1bd61b5ea42cd4f193cb8d0896199705636` | `E2E_QDRANT_IMAGE` |
| `registry:2` | `sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373` | `REGISTRY_IMAGE` |
| `kindest/node:v1.31.4` | `sha256:2cb39f7295fe7eafee0842b1052a599a4fb0f8bcf3f83d96c7f4864c357c6c30` | `NODE_IMAGE` |

Workflow `Load immutable image pins (committed digests, §9)` step:
validates env-key grammar `^[A-Z][A-Z0-9_]*$` and image-name grammar,
verifies each pin against `^sha256:[0-9a-f]{64}$` (anything else —
sentinel, malformed, missing column — aborts the job), pulls and
`docker image inspect`s ONLY `name@sha256:<64hex>`, writes each
`KEY=REF` to `$GITHUB_ENV` **and**
`$E2E_ARTIFACT_DIR/image-provenance-inputs.txt` (exactly six lines),
then exports the three manifest inputs below. The workflow text
contains **no image source name, no bare-tag pull, no resolution
branch, and no sentinel token** (tests enforce all four).

## P1 manifest provenance — exported upstream of the driver

Assigned **before** `Execute golden path driver` (source of truth
upstream of the driver; nothing is patched afterwards):

- `E2E_REGISTRY_DIGEST=<registry:2@sha256:…>` and
  `E2E_KIND_NODE_DIGEST=<kindest/node:v1.31.4@sha256:…>` (pins step).
- `E2E_BASE_IMAGES` — deterministic scalar
  `KEY=value;KEY=value;…` over the six inputs (pins step).
- `E2E_BUILT_IMAGE_DIGESTS` —
  `E2E_WORKLOAD_IMAGE=<name@sha256:…>;REMEDIATION_SANDBOX_IMAGE=<name@sha256:…>`
  from actual post-push `RepoDigests` (build step), each fail-closed
  verified against `@sha256:<64hex>` before export.

The driver's manifest constructor already reads all four env vars
plus `E2E_SOURCE_SHA`/`E2E_FIXTURE_SEED_SHA`/`E2E_WORKSPACES_ROOT`/
`E2E_SANDBOX_DIGEST`. New gate: `finalize_execution_manifest()`
(execution path only) **downgrades PASS → FAIL** with an auditable
`provenance_rejection` reason when any required field
(`source_sha`, `fixture_seed_sha`, `workspace_root`,
`registry_image_digest`, `kind_node_image_digest`, `base_images`,
`built_image_digests`, `sandbox_image_digest`) is empty;
NOT_VERIFIED/BLOCKED preflight paths keep plain `finalize_manifest`,
and dummy unit manifests remain schema-valid without live provenance.

## §6.2 — E2E-built production Dockerfiles eliminated (narrowest fix)

Every surface the workflow builds is digest-controlled — the seven
compose services below plus the workload image:

| Compose service | E2E Dockerfile (built) | Base reference |
| --- | --- | --- |
| `deployment-service` | `deployment_service/Dockerfile.e2e` | `${E2E_PYTHON_BASE_IMAGE:?}` |
| `incident-service` | `incident_service/Dockerfile.e2e` | `${E2E_PYTHON_BASE_IMAGE:?}` |
| `api-gateway` | `api_gateway/Dockerfile.e2e` (new in 8.4.2-D) | `${E2E_PYTHON_BASE_IMAGE:?}` |
| `repo-service` | `repo_service/Dockerfile.e2e` (new) | `${E2E_PYTHON_BASE_IMAGE:?}` |
| `agent-service` | `agent_service/Dockerfile.e2e` (new) | `${E2E_PYTHON_BASE_IMAGE:?}` |
| `monitoring-service` | `monitoring_service/Dockerfile.e2e` (new) | `${E2E_PYTHON_BASE_IMAGE:?}` |
| `incident-event-worker` | `incident_service/Dockerfile.e2e` (override, new) | `${E2E_PYTHON_BASE_IMAGE:?}` |
| workload push | `e2e/workload/Dockerfile` | `${E2E_PYTHON_BASE_IMAGE:?}` |

Production Dockerfiles (`api_gateway/Dockerfile`,
`repo_service/Dockerfile`, `agent_service/Dockerfile`,
`monitoring_service/Dockerfile`, `deployment_service/Dockerfile`,
`incident_service/Dockerfile`) remain **tag-based by design** and are
never part of the E2E build; only the surfaces above are
digest-controlled.

## P2 — raw OAuth token never inherited by child git

`RemediationWorkspaceService._run_git` now strips
`GITHUB_OAUTH_TOKEN` (alongside the existing `GIT_CONFIG_GLOBAL` /
`GIT_CONFIG_SYSTEM` / `GIT_SSH_COMMAND` exclusions) from every child
environment; authentication continues exclusively via caller-supplied
`GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_0=http.extraHeader`/
`GIT_CONFIG_VALUE_0`. Two focused tests
(`TestCredentialHygiene`) capture the real child env: token absent,
header present, unrelated env preserved. No auth redesign.

## Tests (this phase)

- `devops-ai-platform` CI scope: **428 passed + 131 subtests**
  (all 78 prior corrective tests kept — two expectations updated, none
  deleted — plus 25 new: `TestProvenanceClosure` (6),
  `TestCredentialHygiene` (2), `TestDeterministicProvenanceAudit`
  (9 points, Docker-free), parametrization growth over the seven
  E2E Dockerfiles).
- Incident CI 35-module unittest: **Ran 559 — OK (3 skipped)**;
  gateway **79 passed + 60 subtests**; backend **49 passed**;
  harness **24 passed + 7 subtests** (unmodified).
- Workflow static validation: YAML parse OK; `bash -n` on all 15
  `run:` blocks OK; dispatch-only trigger; `permissions: contents:
  read`; both actions full-SHA-pinned; no sentinel token anywhere in
  workflow/pin-file/override.
- Offline resolve-step simulation (stub `docker`, real script): rc=0;
  six digest-only pulls + six digest-only inspects; six-line
  provenance artifact; nine `$GITHUB_ENV` lines (6 pins + 3 manifest
  exports); `E2E_BASE_IMAGES` contains six `@sha256:` refs;
  tightening the grammar check to 63 hex made the step fail closed
  (non-zero).
- `git diff --check`: clean.

## CI run-ID discipline (disclaimer)

Every run ID cited in this report (including the
corrective-hardening evidence above) is an **ordinary `ci.yml` run**
(push or pull_request pattern) executing the CI suites. They are
**not** `E2E Golden Path (staging)` dispatches — no golden-path run
exists (**LIVE E2E: NOT VERIFIED**), and ordinary CI run IDs must
never be relabeled as golden-path evidence. The run IDs for the
8.4.2-D head itself cannot appear inside the commit that defines that
head (self-reference); they are recorded with full job-level detail
in the Phase 8.4.2-D final audit response, which is the evidence
document of record for this phase.

## Remaining blockers (8.4.2-D)

1. Workflow not on the default branch → no dispatch possible
   (**LIVE E2E: NOT VERIFIED**).
2. Fixture repo + `E2E_JWT_SECRET` / `E2E_FIXTURE_GITHUB_TOKEN`
   still unprovisioned (§57 stop honored — all-powerful token NOT
   wired).
3. No Docker/kind/terraform locally → container-level proofs are
   static/unit-level until a real dispatch executes them.

Vocabulary discipline: PASS only for checks that actually ran; every
container/GitHub-dependent property is NOT VERIFIED; no
production-readiness, exactly-once, staging-success, or
"all build inputs are immutable at runtime" claim beyond the
committed-digest facts stated above.
