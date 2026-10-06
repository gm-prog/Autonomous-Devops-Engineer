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
| Integration refs | all five byte-identical to the brief (`1184eb6…`, `4bd799b…`, `3d87007…`, `71713d8…`, `a0bf760…`) — untouched |
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

- main exactly `7b30a56d…`? **YES** (re-verified after push) · five
  integration refs untouched? **YES** (verified byte-identical) · PRs
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
