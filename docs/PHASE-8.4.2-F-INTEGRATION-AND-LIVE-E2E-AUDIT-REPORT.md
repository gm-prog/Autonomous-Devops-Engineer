# Phase 8.4.2-F — Final Audit Report

Clean integration slice and live golden-path E2E enablement.
Audit date: 2026-10-06. All evidence below was produced at the heads named with it.

---

## 1. Executive status

| Dimension | Status |
|---|---|
| **INTEGRATION** | **PASS** — a clean, surgical slice exists and is published as **PR #13** (50 files, 30 linear commits) onto `integration/phase-8.2-v1`, a true ancestor of this work |
| **CI** | **PASS** at the exact final head — push run `37480885467` and `pull_request` run `37480896669`, 5/5 jobs each |
| **DEFAULT-BRANCH WORKFLOW PUBLICATION** | **BLOCKED** — `e2e-golden-path.yml` is absent from the default branch; the workflow is not registered and cannot be dispatched |
| **LIVE E2E** | **BLOCKED / NOT VERIFIED** — the golden path has never executed; no run id exists |

The §4.2 instruction to cut a branch named `phase-8.4.2-f-live-e2e-integration` from
`main` was **not executed**, for two independent reasons documented in §3. The
substitute delivered is strictly safer and measurably smaller.

---

## 2. Starting refs (verified, not assumed)

| Ref | SHA | State |
|---|---|---|
| `main` (local and `origin`) | `7b30a56d2bfd06798c0a90023acd1c6bd5cd3420` | unchanged; **1 commit total** |
| session branch head at phase start | `7499ee04ca6cb5f32ebe37e18efdff990f9fa4ec` | Phase 8.4.2-E1 closure |
| `integration/control-plane-foundation-v1` | `4bd799b3bb1404d713a00ae12ca4f43de6287e6d` | unchanged |
| `integration/phase-8-control-plane-v1` | `3d87007db82f4ca11f207462986d4d54c74cce3d` | unchanged |
| `integration/phase-8.1-v1` | `71713d83b6992a8ec70df00807d7db26759e6669` | unchanged |
| `integration/phase-8.2-v1` | `a0bf7600a25f2821fc61a8fcf3fba9c408667826` | unchanged |
| `integration/remediation-platform-reconciliation` | `1184eb677c6e53178c42fd7c8c1331efd61d00b3` | unchanged |
| `integration/remediation-reconstruction` | `d1961e43ba21725daaaf4f294b369f72c0946fb6` | unchanged |

> The task text spells the last ref `d1961e43ba21725daa4f294b369f72c0946fb6` (38 chars).
> That is a transcription typo; the real 40-hex object is above and the prefix matches.

**Topology facts that determined this phase:**

```
git merge-base main HEAD        -> (empty: unrelated histories)
git rev-list --count main       -> 1
git rev-list --count HEAD       -> 128 (126 at phase start + 2 Phase-F commits)
```

All six integration refs **are ancestors** of this branch. `main` is not.

---

## 3. Clean integration branch

### 3.1 Why `main` is not a usable base

`main` is a single squashed commit that predates the entire platform. Measured,
not inferred:

| Measurement | `base = main` | `base = integration/phase-8.2-v1` |
|---|---|---|
| merge-base with this work | **none** | `a0bf7600` (true ancestor) |
| files changed | **381** | **50** |
| line delta | **+57,953 / −765** | **+9,637 / −5** |
| files *deleted from the base* | **19** | 0 |
| unrelated files modified | **17** (Android app, `backend/`, `mcp/`, `monitoring/`, `README`, `.gitignore`) | 0 |
| commits | 130 | 31 |

`main` carries an older hyphenated prototype (`devops-ai-platform/api-gateway/`,
`incident-service/`, … 72 files) and **no `.github/workflows/` directory at all**.
A `main`-based "slice" would therefore be a whole-platform import that also deletes
`main`'s own files — the opposite of a minimal integration slice, and a direct hit on
stop condition §30 ("the closure cannot be established without importing large
unrelated history") and §28 ("no unrelated feature enters the clean branch").

### 3.2 What was delivered instead

**PR #13** — `arena/b6307a50-autonomous-devops-engineer` → `integration/phase-8.2-v1`.

- 50 files, +9,637 / −5, 31 commits, **0 merge commits** (this report is the 50th file)
- `git diff A...B` and `git diff A..B` return the identical file set (the base is a
  true ancestor, so the PR diff has no merge-base distortion)
- continues the repository's own stacked chain: `#8 → #9 → #10 → #11 → #13`

Nothing was created, rewritten or force-pushed: no new branch, no rebase, no history
rewrite, `main` untouched, all six integration refs byte-identical to §2, and
**PR #12 was not merged, retargeted or modified** (it remains OPEN against `main`, 381 files, `mergedAt: never`).

### 3.3 Disclosed conflict with §4.2

Two independent blockers, either of which alone is sufficient:

1. **Session binding.** This session is fixed to `arena/b6307a50-autonomous-devops-engineer`;
   creating, switching to or pushing `phase-8.4.2-f-live-e2e-integration` is not permitted.
2. **Engineering.** Per §3.1 a `main`-based branch is not a slice. Even with unlimited
   branch freedom, cutting it would violate §28/§30.

`DEFAULT-BRANCH PUBLICATION: BLOCKED`.

---

## 4. Dependency closure

Derived by walking workflow → compose → pins → Python imports → build contexts.
Column "on `main`" was checked with `git ls-tree -r main -- <path>`.

| # | Role | Files | On `main` | Smallest source ref |
|---|---|---|---|---|
| 1 | Golden-path workflow | `.github/workflows/e2e-golden-path.yml` | **ABSENT** | this slice |
| 2 | CI workflow (BuildKit gate) | `.github/workflows/ci.yml` | **ABSENT** (no `.github/` at all) | `integration/phase-8.2-v1` + slice |
| 3 | Compose override | `docker-compose.e2e.yml` | **ABSENT** | this slice |
| 4 | Immutable pins | `e2e/pinned-images.txt`, `e2e/image_pins.py` | **ABSENT** | this slice |
| 5 | E2E helpers / manifest | `e2e/helpers.py`, `e2e/readiness.py`, `e2e/compose_diagnostics.py`, `e2e/__init__.py` | **ABSENT** | this slice |
| 6 | Driver | `e2e/golden_path.py` | **ABSENT** | this slice |
| 7 | Build surfaces (8) | 6 × `*/Dockerfile.e2e`, `e2e/workload/Dockerfile`, `e2e/sandbox/Dockerfile`, inventory `e2e/build_surfaces.py` | **ABSENT** | this slice |
| 8 | Cluster/fixture assets | `e2e/kind-config.yaml`, `e2e/fixtures/*` (4), `e2e/terraform/main.tf`, `e2e/workload/server.py` | **ABSENT** | this slice |
| 9 | Deployment / incident / remediation services | `incident_service/application/services/{remediation_validation_runner,remediation_workspace_service,validation_sandbox}.py`, `incident_service/presentation/rest/controllers.py` | **ABSENT** (only an unrelated prototype of the same name) | `integration/phase-8.2-v1` + slice |
| 10 | RCA → proposal seam | `agent_service/application/deterministic_rca.py`, `agent_service/presentation/rest/rca_controller.py`, `agent_service/main.py`, `api_gateway/routers/control_plane.py` | **ABSENT** | this slice |
| 11 | Sandbox policy | `incident_service/application/services/validation_sandbox.py` | **ABSENT** | `integration/phase-8.2-v1` + slice |
| 12 | Fixture contract | `tests/fixtures/e2e_fixture_repo/src/service_config.py` | **ABSENT** | this slice |
| 13 | Tests (7) | `tests/test_e2e_{corrective,harness,validation_profile}.py`, `tests/test_{agent_rca_boundary,deployment_evidence_route,deterministic_proposal_path}.py`, `api_gateway/tests/test_incident_control_plane_routes.py` | **ABSENT** | this slice |
| 14 | Phase documentation | 6 × `docs/PHASE-8.*.md` | **ABSENT** | this slice |

**Closure result: 0 of the 49 required implementation files exist on `main`.** Relative to `main` the
closure additionally pulls in the six service packages that the Dockerfiles copy as
build context (`COPY . /app` over `devops-ai-platform/`), i.e. a further ~292 files
that `main` has never carried. Relative to `integration/phase-8.2-v1` the closure is
exactly the 49 files above and nothing else (plus this report, committed after them).

**§8 strategy outcome:** Strategy A (`cherry-pick -x`) was unnecessary and Strategy C
(bounded merge) unsafe against `main`. The slice is the natural linear range
`a0bf7600..HEAD`, published as-is — no reconstruction, no rewriting, no synthetic commits.

---

## 5. Diff / scope audit

> Line counts in this report are measured at head `96ee094`; the commit that
> records these corrections adds a few further lines to this file alone.

**Phase 8.4.2-F changed exactly 4 files in 2 commits** (`b08fbb0`, `c69c28d`):

```
.github/workflows/e2e-golden-path.yml      (§21-F deny-case inside existing step 2)
devops-ai-platform/e2e/helpers.py          (+ PRODUCTION_REPOSITORY, is_production_repository)
devops-ai-platform/e2e/golden_path.py      (preflight wiring)
devops-ai-platform/tests/test_e2e_corrective.py  (+14 tests)
```

Verified untouched at the final head: `main`; all six integration refs; the C/D/E1
commits (`be19a4e`, `a80fb28`, `d97d667`, `88ac121`, `39d466f`, `12ab603`, `7499ee0`
are all still ancestors of HEAD); **all six committed digests byte-identical**
(`git diff 7499ee0..HEAD -- e2e/pinned-images.txt` is empty); **0 production
Dockerfiles changed** (all six remain `FROM python:3.11-slim`); Android app, `backend/`,
`mcp/`, `monitoring/`, `k8s/`, `terraform/`, DB schema, execution leases, RCA/proposal
semantics and the GitHub PR safety adapter all untouched. Working tree clean.

**E1 invariants re-verified at the final head:** `build_surfaces.validate_all()`
returns no problems for **8/8** surfaces; the four-line contract
(`# syntax=docker/dockerfile:1@sha256:4edf897a…`, `# check=skip=InvalidDefaultArgInFrom;error=true`,
`ARG BASE_IMAGE`, `FROM ${BASE_IMAGE}`) is intact; the workflow is still 17 steps,
`workflow_dispatch`-only, `environment: e2e-staging`, `permissions: contents: read`.

---

## 6. CI evidence (exact final head only)

Head `c69c28d7d48dc8216567b534e5dd47e2480aba77`:

| Run | Event | Jobs | Conclusion |
|---|---|---|---|
| `37480885467` | `push` | 5/5 success | **success** |
| `37480896669` | `pull_request` | 5/5 success | **success** |

Jobs: API gateway checks, Backend tests, Incident/RCA/remediation checks, Compose
validation, Platform smoke tests.

BuildKit gate, `Compose validation` step 5 "E2E Dockerfile build contract (BuildKit)":
**success**, `2026-10-06T14:40:17Z → 14:40:28Z`. Annotation text at this head:

```
docker server 28.0.4
github.com/docker/buildx v0.37.1 0b265a9f62db554fa9aba6dd19e1bd5704bc7d8a
committed BASE_IMAGE = python@sha256:0dd364ba7e10242f07755449e3a3d0e35f9efd987952737b90def6709ab0c5ce
static contract OK for 8 E2E Dockerfiles
<8 lines, one per surface> digest-arg=pass no-arg=rejected
mutation probe rejected: ERROR: dockerfile parse error on line 3: FROM requires either one or three arguments
negative-check sample: ERROR: base name (${BASE_IMAGE}) should not be blank
surfaces checked=8 failures=0
```

The docs-only commit that adds this report was verified separately at head
`c678cd0`: push `37481797888` and `pull_request` runs `37481808638` / `37481809860`,
5/5 jobs each, BuildKit gate step 5 success `14:46:44Z → 14:46:51Z`.

**Local §18 matrix at the final head** (venv Python 3.11, no Docker, no secrets):

| Suite | Result |
|---|---|
| `tests/test_e2e_corrective.py` | **217 passed** (203 → 217) |
| `tests/test_e2e_harness.py` | **31 passed, 18 subtests** |
| `pytest tests/ deployment_service/tests` | **549 passed, 142 subtests** (535 → 549) |
| api_gateway (`JWT_SECRET=ci-gateway-secret`) | **79 passed, 60 subtests** |
| incident 35-module unittest list from `ci.yml` | **Ran 559, OK (3 skipped)** |
| `backend` | **49 passed** |
| `compileall`, `git diff --check` | OK / clean |
| workflow YAML parse, `bash -n` × 28 run-blocks | OK / 0 failures |

**Count-change explanation (§18):** corrective 203 → **217** and platform 535 → **549**
are the *same* +14 tests — the single new class `TestFixtureRepositoryIsNeverProduction`
(6 production spellings rejected, 5 disposable fixtures accepted, 1 constant check,
1 driver-wiring check, 1 workflow-ordering check). No prior test was weakened, skipped
or deleted; harness, api_gateway, incident and backend counts are unchanged.

---

## 7. Workflow publication status

**BLOCKED.** Evidence, all collected live:

```
gh api .../actions/workflows            -> total_count: 1
                                           364339660  CI  [.github/workflows/ci.yml]
gh workflow run e2e-golden-path.yml     -> HTTP 404: Not Found
gh api -X POST .../workflows/e2e-golden-path.yml/dispatches -f ref=main
                                        -> HTTP 403 "Resource not accessible by integration"
gh run list --limit 200 | unique names  -> ["CI"]   (200 runs, zero golden-path runs)
```

GitHub registers `workflow_dispatch` workflows only from the **default branch**.
`e2e-golden-path.yml` exists solely on this branch, so it is not registered: the 404 is
the API stating the workflow does not exist, not a permissions artifact. The subsequent
403 on the explicit REST path is a *second, independent* blocker (§8.5).

---

## 8. External prerequisites

Reported as status only; no value of any secret was read, printed or persisted.

| # | Prerequisite | Status | Evidence |
|---|---|---|---|
| 8.1 | `e2e-staging` environment | **MISSING** | `gh api .../environments` → `{"total_count":0,"environments":[]}` — the repository has no environments at all |
| 8.2 | `E2E_JWT_SECRET` | **MISSING** | cannot exist: no environment to scope it to |
| 8.3 | `E2E_FIXTURE_GITHUB_TOKEN` | **MISSING** | as above |
| 8.4 | `gm-prog/ares-e2e-fixture` | **MISSING / NOT INSPECTABLE** | `gh api repos/gm-prog/ares-e2e-fixture` → HTTP 404 |
| 8.5 | Dispatch capability of the available credential | **ACCESS DENIED** | REST dispatch → 403 `Resource not accessible by integration`: this is a GitHub App installation token, which cannot create `workflow_dispatch` events even though repo metadata reports `admin: true` |
| 8.6 | 40-hex immutable `fixture_seed_sha` | **NOT AVAILABLE** | no fixture repository exists, therefore no seed commit exists |

**Why this was not "fixed" by the agent.** Provisioning would require minting a
`E2E_FIXTURE_GITHUB_TOKEN`. An agent cannot mint a PAT, and the only alternative —
embedding the session credential — is explicitly prohibited (§12), as are widening
permissions, making the fixture public and bypassing the environment. The honest
outcome is an external blocker, not a workaround.

---

## 9. Live E2E evidence

**None. LIVE E2E: NOT VERIFIED.**

No run id, no job ids, no head SHA, no workflow-file SHA, no seed SHA, no manifest —
because the workflow has never executed (§7). Nothing in this report infers execution
from CI colour, YAML validity, `buildx --check` success or a previous report.

What *is* proven about the live path is strictly its static contract: the BuildKit gate
(§6) proves the eight Dockerfiles build-plan correctly with the committed digest and are
rejected without it. `--check` does not build an image; real image builds, compose
startup, kind, registry, the authenticated private fixture, the remediation path, the
sandbox run and the manifest remain **NOT VERIFIED**.

---

## 10. Security and provenance audit

| Control | Status at final head |
|---|---|
| Digest path pin-file → `image_pins --refs` → `$GITHUB_ENV` → compose → `BASE_IMAGE` → `ARG`/`FROM` | intact |
| `UNRESOLVED` sentinel / `manifest inspect` / tag resolution at dispatch | 0 occurrences |
| Workflow trigger | `workflow_dispatch` only; `pull_request_target` appears once, in a comment at line 4 |
| Permissions | `contents: read` |
| Secret scoping | 9 `secrets.*` references, all step-scoped; 0 at job level |
| Token hygiene | 0 `x-access-token` embeds, 0 `GIT_ASKPASS`, 0 tokens in clone URLs or argv |
| Step ordering | registry+kind (#6) → build (#7) → publish (#8) → compose (#10) → driver (#13) → secret scan (#15) → upload (#16) |
| Sandbox policy | unchanged: `--pull never`, `--network none`, `--read-only`, `--cap-drop ALL`, `no-new-privileges:true`, non-root `--user`, `--pids-limit`, `--memory`, `--cpus`, exactly one `:ro` bind; no Docker socket |
| Manifest fail-closed | `finalize_execution_manifest()` downgrades PASS→FAIL on any empty required field |

### §21 mutation matrix — executed, not asserted

| # | Mutation | Required outcome | Observed |
|---|---|---|---|
| **A** | Workflow absent from default branch | `WORKFLOW_PUBLICATION_FAILURE` | **CONFIRMED LIVE** — this is the current state: dispatch → HTTP 404 (§7) |
| **B** | `E2E_JWT_SECRET` missing | blocked pre-execution | **CONFIRMED** — workflow step 2 exits 1 with `protected e2e-staging secrets are not provisioned`, before toolchain install, build and kind; `golden_path.preflight()` independently returns `BLOCKED` |
| **C** | Mutable tag in pins | hard fail pre-build | **CONFIRMED — 7/7 variants rejected** by `parse_pinned_images`: mutable tag, `UNRESOLVED` sentinel, truncated digest, `latest`, dropped pin column, removed required key, duplicate env key |
| **D** | Malformed `fixture_seed_sha` | preflight failure | **CONFIRMED** — `validate_sha40` rejects empty, non-hex, 39-char, 41-char, uppercase and `g…`; accepts only 40 lowercase hex. Workflow re-checks with `grep -Eq '^[0-9a-f]{40}$'` |
| **E** | Blanked provenance field | manifest FAIL | **CONFIRMED — all 8 fields** (`source_sha`, `fixture_seed_sha`, `workspace_root`, `registry_image_digest`, `kind_node_image_digest`, `base_images`, `built_image_digests`, `sandbox_image_digest`) individually downgrade PASS→FAIL with `provenance_rejection` set |
| **F** | Fixture repo = production | prohibited | **GAP FOUND AND CLOSED THIS PHASE** — see below |
| **G** | Weakened sandbox flags | audit failure | **CONFIRMED by live mutation** — flipping `no-new-privileges:true` → `:false` fails `test_validation_sandbox.py::PrivilegeHardeningTests::test_hardening_flags_present_and_dangerous_ones_absent`, which is in the `ci.yml` 35-module list; file restored, tree clean |

**Finding F (the one real defect this phase uncovered).** The only guard on
`E2E_FIXTURE_REPOSITORY` was a slug *shape* check — `gm-prog/Autonomous-Devops-Engineer`
satisfies it. The prohibition was structural (the value is a hardcoded workflow env, not
a dispatch input) but never asserted, so a single-line edit to the workflow would have
pointed a run that pushes branches and opens PRs at production source. Closed by
`helpers.is_production_repository()` (insensitive to case, whitespace, trailing `.git`
and trailing slashes), a `preflight()` rejection, and a workflow deny-case ordered before
the first `docker build` and `kind create cluster`. Verified: the production slug in six
spellings is rejected; `gm-prog/ares-e2e-fixture` is accepted.

---

## 11. Remaining blockers

| # | Blocker | Class (§17) | Owner |
|---|---|---|---|
| 1 | `e2e-golden-path.yml` is not on the default branch → not dispatchable | `WORKFLOW_PUBLICATION_FAILURE` | repository owner: land the chain `#8 → #9 → #10 → #11 → #13` (or publish the workflow to `main` by whatever policy applies) |
| 2 | `e2e-staging` environment does not exist | `ENVIRONMENT_PREREQUISITE_FAILURE` | repository owner |
| 3 | `E2E_JWT_SECRET` not provisioned | `ENVIRONMENT_PREREQUISITE_FAILURE` | repository owner |
| 4 | `E2E_FIXTURE_GITHUB_TOKEN` not provisioned; an agent cannot mint a PAT | `CREDENTIAL_CAPABILITY_FAILURE` | human operator |
| 5 | `gm-prog/ares-e2e-fixture` does not exist (must be **private**, must never be the production repo) | `FIXTURE_REPOSITORY_FAILURE` | repository owner |
| 6 | No 40-hex seed commit to pass as `fixture_seed_sha` | `FIXTURE_REPOSITORY_FAILURE` | follows from #5 |
| 7 | The available credential is an App installation token that cannot create dispatch events | `CREDENTIAL_CAPABILITY_FAILURE` | human operator |
| 8 | `main` and this work have no common ancestor; whether the platform supersedes `main`'s prototype is a repository-policy decision | `INTEGRATION_FAILURE` (deliberately not auto-resolved) | repository owner |

Blockers 1–7 must all clear before a first live run is even attemptable, in that order.

---

## 12. Hostile audit — Q1–Q14

**Q1. Is "CI is green" being passed off as "the golden path ran"?**
No. §6 is scoped to CI at `c69c28d`; §9 states no live run exists. The two are never
combined into a single claim.

**Q2. Was the branch required by §4.2 created?**
No, and that is disclosed in §3.3 with both reasons. No synthetic equivalent was passed
off as it.

**Q3. Is the slice actually minimal, or just asserted to be?**
Measured: 50 files / +9,637 −5 against `integration/phase-8.2-v1`, versus 381 files /
+57,953 −765 against `main`. Both numbers come from `git diff --stat` and are corroborated
by GitHub's own counts on PR #13 (50) and PR #12 (381).

**Q4. Could the slice have been even smaller?**
The six `docs/PHASE-8.*.md` files are not needed to execute the golden path. They were
retained because they are the audit trail for the same commits and removing them would
require rewriting history, which is prohibited. Every non-doc file is reachable from
the workflow by the walk in §4.

**Q5. Does PR #13 drag in unrelated history?**
No. `integration/phase-8.2-v1` is a true ancestor (`git merge-base --is-ancestor` → true),
the range has 0 merge commits, and three-dot and two-dot diffs are identical.

**Q6. Was PR #12 merged, retargeted, closed or used as a shortcut?**
No. It is still OPEN at `main`, 381 files, `mergedAt: never`. PR #13 is a
separate PR from the same head to a different base — a supported GitHub operation that
mutates neither #12 nor the base ref.

**Q7. Did anything touch `main` or the six integration refs?**
No. All seven SHAs in §2 were re-read from `origin` after the final push and are unchanged.

**Q8. Were the E1 digests or the Dockerfile contract disturbed?**
No. `git diff 7499ee0..HEAD -- e2e/pinned-images.txt` is empty and `validate_all()` reports
8/8 surfaces conforming at the final head.

**Q9. The test count moved from 203 to 217 — was a test weakened to get green?**
No. The delta is exactly the 14 new §21-F tests in one new class; the suite was 217/217
green on the first full run after the fix. Harness (31+18), api_gateway (79+60), incident
(559) and backend (49) are unchanged, which is what a pure addition looks like.

**Q10. Were the mutation results observed or reasoned?**
C, D, E and G were executed in this session against the real modules, with the outputs in
§10; G was a real file mutation followed by restoration (tree verified clean). A is the
live current state (404 from the dispatch API). B is read from the workflow's own step
plus `preflight()`; it is the one entry that is static, and it is labelled as such.

**Q11. Is the §21-F fix scope creep?**
It is inside the phase's explicit mutation matrix and it closed a real path by which an
E2E run could have mutated production source. 4 files, 2 commits, no behaviour changed for
the legitimate fixture.

**Q12. Could the agent have provisioned the environment itself, given `admin: true`?**
Repo metadata says `admin: true`, but the same credential gets 403
`Resource not accessible by integration` on dispatch — it is an App installation token, so
the admin flag is not decisive. Regardless, `E2E_FIXTURE_GITHUB_TOKEN` requires minting a
PAT, which an agent must not do, and embedding the session credential is prohibited.
Provisioning was therefore not attempted.

**Q13. Does merging PR #13 make the golden path dispatchable?**
No. It makes the workflow present on `integration/phase-8.2-v1` only. Dispatchability
requires presence on the **default branch**, i.e. blockers 1–3 and 5 in §11.

**Q14. If every prerequisite were provisioned tomorrow, would the run pass?**
Unknown, and this report does not predict it. Everything beyond the static contract —
real image builds, registry/kind, compose readiness, the authenticated private fixture,
the remediation path, the sandbox run, manifest completeness — has never executed once.
The correct reading is `NOT VERIFIED`, not "expected to pass".

---

## 13. Final recommendation

**MERGE-READY (integration chain) + LIVE-E2E-BLOCKED.**

- **MERGE-READY:** PR #13 is a clean, minimal, reviewable 50-file slice onto a true
  ancestor, green in CI at its exact head, with every Phase 8.4.2 invariant re-verified.
  It is the correct vehicle for landing Phase 8.4.2 — not PR #12.
- **LIVE-E2E-BLOCKED:** the first live golden-path run cannot be attempted until §11
  blockers 1–7 are cleared by the repository owner. Until a real run exists at a named
  commit with a complete manifest, the standing status is **LIVE E2E: NOT VERIFIED**.
- **Not recommended:** merging PR #12, importing this work directly into `main`, or
  treating "CI green" or this report as evidence that the golden path works.
