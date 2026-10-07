# Phase 8.5-A — Closeout Publication Record

This document exists so a reviewer can determine, without reading any
chat transcript or pull-request description, **exactly which code was
executed, which CI run proved it, which artifact holds the evidence, and
what remains unverified.**

Every number here was recomputed from Git or the GitHub API at closeout
time. None of it is copied from an earlier report. Where an earlier
report was wrong, the error is named in §6.

---

## 1. Review surface

| Question | Answer |
| --- | --- |
| Branch holding the implementation | `arena/b6307a50-autonomous-devops-engineer` |
| Integration base | `integration/phase-8.2-v1` @ `a0bf7600a25f2821fc61a8fcf3fba9c408667826` |
| Is the integration base an ancestor of the head? | **Yes** |
| `merge-base(integration/phase-8.2-v1, HEAD)` | `a0bf7600…` — identical to the integration base head |
| Commits behind the integration base | **0** |
| Merge commits since the integration base | **0** (strictly linear) |
| Commits since the integration base | **67** |
| Files changed since the integration base | **87** |

**Consequence.** The branch is already a clean, linear, fast-forwardable
descendant of `integration/phase-8.2-v1`. A publication branch cut from
that base would contain *byte-identical* trees to this branch. There is
no merge debris, no back-merge from `main`, and no unrelated experiment
in the lineage — §5 below enumerates every commit.

---

## 2. Commit roles (the circularity problem, stated explicitly)

A commit cannot contain the hash of itself. These three roles are
therefore deliberately distinct:

| Role | SHA | Meaning |
| --- | --- | --- |
| **Implementation commit** | `246a7f3ecf7e01e36a057f9c09247065462d00a4` | Last commit changing non-documentation files |
| **Proof commit** | `80ec0d483e4e56f22c720dfd4a09a56bde49a6f6` | The tree GitHub Actions checked out and executed |
| **Evidence publication commit** | resolve with `git log --diff-filter=AM --format=%H -1 -- docs/phase-8.5-a-closeout-provenance.json` | The commit publishing this record |

`246a7f3` is the **parent** of `80ec0d4`; the only delta between them is
`docs/phase-8.5-a-closeout-evidence.json`:

```
git diff --name-only 246a7f3..80ec0d4
  docs/phase-8.5-a-closeout-evidence.json
```

So the code that ran under the proof commit is exactly the code
introduced by the implementation commit. Machine-readable form:
`docs/phase-8.5-a-closeout-provenance.json`.

---

## 3. Evidence lineage

| Field | Value |
| --- | --- |
| Workflow run | `37595291239` |
| Run head SHA | `80ec0d483e4e56f22c720dfd4a09a56bde49a6f6` |
| Run conclusion | `success` (9 / 9 jobs) |
| Live E2E job | `112706334202` — "Phase 8.5-A containerized deployment-service E2E" |
| Live E2E job conclusion | `success` |
| Artifact | `11470447669`, `terraform-container-e2e-evidence`, 1879 bytes |
| Artifact digest | `sha256:f90ed407bc95c0b94ca1a4a9fa5b05917a3205b14ff6b1e13b35ac53d1f85f88` (API metadata) |
| Evidence file | `docs/phase-8.5-a-closeout-evidence.json` |
| Evidence sha256 | `48c29beebbcef91d59a21fd56491ea3bd86b24e60bb42f9f5c5445a43515bade` |

**Artifact verification limitation — stated plainly.** The artifact
*download* is unreachable from the build environment (blob storage
returns `EOF`). The zip bytes were never opened, so the digest above is
**API metadata, not a locally recomputed hash**. The evidence *content*
was instead recovered byte-exact from the job's own annotations and
verified against the sha256 the job itself published — those two hashes
match. No byte-level claim is made about the zip.

---

## 4. Claim table (§10 audit)

| Claim | Source | Referenced commit | Referenced CI run | Current status |
| --- | --- | --- | --- | --- |
| `LIVE E2E: PASS` | `PHASE-8.5-A-…-TRUST-BOUNDARY.md` §7 | — (points at evidence file, not a hard-coded SHA) | — | **Current** |
| 39/39 checks PASS | `phase-8.5-a-closeout-evidence.json` | `80ec0d4` | `37595291239` | **Current** |
| `approved == applied` plan hash | same | `80ec0d4` | `37595291239` | **Current** |
| Runtime security observations | same + doc §7 table | `80ec0d4` | `37595291239` | **Current** |
| Sandbox image digest | same (registry-resolved at run time) | `80ec0d4` | `37595291239` | **Current** |
| Corrective-phase evidence file | `phase-8.5-a-corrective-evidence.json` | `d6acc32` | `37588864343` | **Deleted** in `dde5268` — stale, must not be cited |
| In-process live E2E (19/19) | `e2e/terraform_sandbox_live.py` | `4d9283e` | `37589026913` | **Superseded & deleted** — ran outside the service container; not Gate-A proof |

No stale claim remains in the tree. Verified: the trust-boundary
document contains no commit SHA and no workflow run ID, so it cannot go
stale against a moving head.

---

## 5. Phase map of the 67-commit lineage

| Range | Commits | Phase |
| --- | --- | --- |
| `7ead35e … 7f0290f` | 7 | Phase 8.3 / 8.3.1 / 8.3.2 integration publication |
| `9014926 … 1eedb5e` | 5 | Phase 8.4 control-plane seams, deterministic RCA |
| `d16f2bd … e44d6c6` | 34 | Phase 8.4.2 (A → G.1) golden path, provenance, audit truth, evidence contract |
| `d4e87a5` | 1 | **Phase 8.5-A original** — sandbox implementation |
| `ddac68c … 4d9283e` | 9 | **Phase 8.5-A corrective** — approval integrity + runnable sandbox |
| `dde5268 … 80ec0d4` | 11 | **Phase 8.5-A closeout** — containerized service E2E + evidence |

Exact counts (`git rev-list --count`, exclusive of the base):

```
integration/phase-8.2-v1..HEAD  = 67
d4e87a5..HEAD                   = 20
4d9283e..HEAD                   = 11
```

---

## 6. Corrections to the previous report

| Item | Previously reported | Correct value | Cause |
| --- | --- | --- | --- |
| Commits vs `d4e87a5` | 19 | **20** | The count was taken at `246a7f3` and then reported against final head `80ec0d4`, which is one commit later |
| Platform smoke test result | `910 passed` | **depends on checkout depth — see §7** | A full clone and CI's shallow clone legitimately differ |

Both are reporting errors, not implementation changes.

---

## 7. Test-count reconciliation (§16)

The difference is real, explained, and reproducible — not a discrepancy
to be papered over.

| Environment | Command | Result |
| --- | --- | --- |
| **CI** (`actions/checkout@v4`, default `fetch-depth: 1`, shallow) | `pytest tests/ deployment_service/tests` | **909 passed, 1 skipped, 1 warning, 142 subtests** |
| **Local full clone** (unshallowed) | same | **910 passed, 0 skipped, 1 warning, 142 subtests** |
| Collected in both | — | **910** |

The single differing test is
`tests/test_audit_phase_8_4_2_f.py::test_committed_audit_record_matches_this_repository`,
which calls `git rev-parse --is-shallow-repository` and skips itself when
the checkout is shallow, because it cannot verify repository topology
without history.

This was reproduced directly, by cloning the repository with
`--depth 1` and running the same command — the shallow clone produced
`909 passed, 1 skipped`.

That test is **not** skipped everywhere: the `Phase 8.4.2-F audit truth`
job is the only job configured with `fetch-depth: 0`, and it asserts the
test **executes and passes** rather than skipping, failing the job if it
is skipped or not collected.

### Full suite results (local, full clone, at the proof commit)

| Suite / CI job | Result |
| --- | --- |
| `pytest tests/ deployment_service/tests` — Platform smoke tests | 910 collected · 910 passed · 0 skipped · 142 subtests · 1 warning |
| `pytest tests/` — Backend tests | 631 passed · 108 subtests · 1 warning |
| `pytest deployment_service/tests` | 279 passed · 34 subtests · 1 warning |
| `pytest deployment_service/tests/test_terraform_trust_boundary.py` | 134 passed |
| `pytest deployment_service/tests/test_terraform_approval_integrity.py` | 58 passed |
| `pytest api_gateway/tests` — API gateway checks | 95 passed · 78 subtests · 1 warning |
| `pytest tests/test_operational_evidence_contract.py api_gateway/tests/test_evidence_plane.py` — G.1 | 147 passed · 18 subtests · 1 warning |
| Incident / RCA / remediation (`unittest`) | Ran 559 · OK · skipped=3 |
| AST host-execution guard | exit 0, 5 modules CLEAN |
| Mutation probes | 20 total · 17 CAUGHT · 3 LAYERED · 0 ESCAPED |
| Containerized live E2E | 39 / 39 PASS |

`631 + 279 = 910`, consistent with the collected total.

---

## 8. Authoritative E2E driver (§20)

There is exactly one authoritative live E2E:

```
authoritative live E2E = devops-ai-platform/e2e/terraform_sandbox_container_e2e.py
                         CI job "Phase 8.5-A containerized deployment-service E2E"
```

The superseded host-direct driver `e2e/terraform_sandbox_live.py` was
**deleted** in `dde5268`. It constructed `DeploymentEngine(...)` inside
the CI runner process, so it never exercised the deployment-service
container and its probes were weaker (notably a `touch`-based rootfs
check that cannot distinguish a read-only mount from ordinary permission
denial). Zero references to it remain anywhere in the tree. No competing
"authoritative" E2E path exists.

Unit coverage was **not** removed in favour of the E2E: the trust
boundary (134 tests), approval integrity (58 tests), the AST guard and
the 20 mutation probes all remain and all run in CI. Unit tests and the
live E2E prove different things and both are required.

---

## 9. Residual risk

* **Docker socket on the trusted control plane.** The deployment-service
  container mounts `/var/run/docker.sock`. That grants it effective root
  on the host daemon. A compromise of control-plane code can therefore
  reach the Docker daemon. The socket is never propagated into the
  Terraform workload (proved: `ABSENT` inside the sandbox), but the
  service itself is **not** host-isolated and this phase does not claim
  it is. A dedicated sandbox-runtime service remains the preferred end
  state.
* **Approval artifacts are ephemeral.** The approved plan lives in a
  workspace directory, not durable storage. If it disappears, execution
  **fails closed** (proved: `DEPLOYMENT_FAILED`, no silent re-plan)
  rather than regenerating a plan.
* **`--network none` precludes providers.** The zero-cloud fixture uses
  only the built-in `terraform_data` resource, so `.terraform/` is
  legitimately absent and no real cloud provider path is exercised.
* **Kubernetes is stubbed** at the test topology and is **not** validated
  by this result.
