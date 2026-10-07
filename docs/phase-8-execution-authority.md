# Phase 8.2 — Execution Authority & Compatibility Semantics

Status vocabulary: **implemented**, **tested locally**, **tested in CI**,
**known limitation**, **not verified**. Delivery/execution is described
only as:

> **at-least-once + deterministic idempotency + CAS + lease +
> reconciliation + fail-closed**

The phrase "exactly-once execution" is never used.

## 15.1 Authoritative path

```text
Incident
  ↓ trusted deployment evidence (DEPLOYED, provenance, same-record binding)
RCA (persisted rca_result evidence)
  ↓ canonical HotfixProposal, deterministic identity `proposal-{incident_id}`
deterministic hash (compute_proposal_hash)
  ↓ PROPOSED                    ← compatibility intake may land HERE only
explicit operator approval of exact hash (JWT `sub` stamped by gateway)
  ↓ APPROVED                    ← proposal_approval_service is the only writer
ProposalExecutionService.execute()
  ↓ hash re-verification → approval freshness → patch-policy revalidation
  ↓ authoritative deployment-target revalidation
durable execution lease (claim_execution_lease)
  ↓ live lease checks
RemediationOrchestrationService
  ↓ workspace → patch → sandboxed validation → commit → publish → GitHub PR
atomic PR_CREATED persistence (finish_execution_lease, one transaction:
   proposal PR_CREATED + incident RemediationPRCreated + claim FREE +
   evidence + aggregate version +1)
```

No other path may enter below the PROPOSED line.

## 15.2 Forbidden paths (retired)

| Retired surface | Phase | What it could do | Now |
| --- | --- | --- | --- |
| `POST /v1/incidents/{id}/remediation` executing the orchestrator | 8.1 | validate → authorize → execute → PR without approval | compatibility shim: validates, authorizes, persists **PROPOSED/BLOCKED**, returns `next_step` — zero side effects (spy-proven) |
| `ApplyAutomatedFixCommandHandler` (`application/commands/apply_automated_fix.py`) | 8.2 | validate → accept caller repository/branch → `github.create_pull_request` → attach + persist | **module deleted** (Option B: zero runtime callers); `test_execution_authority.py` pins its absence |
| `IncidentAggregate.attach_remediation_proposal()` | 8.2 | append proposal + promote to `RemediationProposed` with no state/identity/protected-state guards | **method deleted**; only `upsert_remediation_proposal` / `attach_blocked_proposal` remain (both guarded, both version-CAS persisted) |

Any future reintroduction of these shapes fails the repository audit in
`incident_service/application/commands/test_execution_authority.py`
(`RepositoryExecutionBoundaryAuditTests`, exact-match allowlist).

## 15.3 Mutation ownership (who may touch Git/GitHub)

| Primitive | Only allowed production file(s) |
| --- | --- |
| `create_pull_request(` | `remediation_orchestration_service.py` (call), `github_pr_client.py` (client implementation) |
| `create_branch_from_commit(` | `remediation_orchestration_service.py`, `github_pr_client.py` |
| `publish_branch(` | `remediation_orchestration_service.py` (call), `remediation_workspace_service.py` (implementation) |
| `reconcile_and_create_pr(` | `proposal_execution_service.py` (call), `remediation_orchestration_service.py` (implementation) |
| raw `git push/clone/checkout/commit` strings | none in `incident_service` production code (argv-form subprocess confined to the workspace/commit/patch/validation services below the orchestration boundary) |
| `RemediationOrchestrationService` construction | `presentation/rest/controllers.py::get_remediation_orchestrator` — the factory seam, injected **only** into `ProposalExecutionService` |
| `orchestrator.execute(` / `orchestrator.reconcile_and_create_pr(` | `proposal_execution_service.py` |

Everything else — REST controllers, legacy commands, event handlers,
workers, proposal generation, approval, the compatibility shim — is
read/approval/control logic with **no** mutation capability.

## 15.4 Approval ownership

Exactly one production writer of `proposal.status = "APPROVED"` and
`proposal.approved_by`:

```text
POST /proposal/approve (gateway stamps approved_by = JWT sub)
  → ProposalApprovalService.approve()
      → proposal hash verification → freshness → risk bound → target reapproval
      → save_incident (version CAS)
```

There is no automatic approval, no approval embedded in execution, no
approval in any command, and no compatibility-field approval. Tests may
seed `status="APPROVED"` fixtures directly; no production path does.

## 15.5 Execution ownership

Exactly one canonical execution service:

```text
POST /proposal/execute → ProposalExecutionService.execute()
    → orchestrator factory → RemediationOrchestrationService
```

`PR_CREATED` has exactly one writer (`proposal_execution_service`) and
exactly one persistence route (`finish_execution_lease`: claim CAS +
terminal transaction, version +1 once). The durable lease stays
authoritative — no process-local locks, timestamps, UUID version tokens,
Redis-only locks, or in-memory state replace it.

## 15.6 Compatibility semantics (retained legacy fields)

Classification for every field still accepted by the compatibility
intake (`RemediationRequest` / former command schema):

| Field | Class | Behavior |
| --- | --- | --- |
| `repository_slug` | identity candidate | accepted only after same-record proof against the incident's DEPLOYED evidence (canonical `owner/repo` form; bare names, URLs, scp strings, path tricks rejected at validation) |
| `source_sha` | identity candidate | accepted only as exact match to the evidence-bound 40-hex SHA (case-normalized, never trusted raw) |
| `target_filepath`, `patch` | payload | syntax-validated through `HotfixValidationService`; unsafe → 422 with BLOCKED proposal persisted |
| `base_branch` | deprecated compatibility | accepted for schema compatibility; **never** execution authority (allowlist policy lives in execution, not in this field) |
| `pr_title`, `pr_body` | presentation metadata | may affect display only; ignored by intake (the shim never opens a PR) |
| `validation_profile` | deprecated compatibility | recorded in `validation_plan`; cannot alter authorization or reach GitHub |
| `confidence_score` | risk input | feeds the deterministic risk classifier; risk is metadata, never an execution trigger |
| former `source_branch` | removed with the retired command | no longer exists on any retained interface |

No compatibility field grants approval, execution, branch authority,
GitHub publication authority, target-binding bypass, or hashing bypass.

## 15.7 At-least-once wording (mandatory)

The system provides:

> **at-least-once + deterministic idempotency + CAS + lease +
> reconciliation + fail-closed**

- *at-least-once*: work (events, execution attempts) may be observed or
  retried more than once;
- *deterministic idempotency*: proposal identity is
  `proposal-{incident_id}` — repeats converge on one logical proposal;
- *CAS*: every aggregate write is gated by
  `UPDATE … WHERE id AND version = expected` (Phase 8.1);
- *lease*: exactly one live execution owner per claim, enforced
  durably;
- *reconciliation*: remote state (branches/PRs) is reconciled, not
  assumed;
- *fail-closed*: stale, unauthorized, or ambiguous input raises a typed
  error (403/409/422) instead of proceeding.

Never write "exactly-once execution".
