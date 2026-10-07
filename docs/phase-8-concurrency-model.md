# Phase 8.1 — Durable Aggregate Concurrency Model

Status vocabulary (Phase 8 rule): **implemented** = code exists;
**tested locally** = green in this sandbox; **tested in CI** = GitHub
Actions run on the exact SHA; **known limitation** = bounded, documented.
This document uses only those words. It never claims *exactly-once*
delivery or execution: the platform provides **at-least-once processing +
idempotency + compare-and-set (CAS) + lease + reconciliation +
fail-closed** semantics, which is what the tests demonstrate.

## 1. The invariant

`IncidentAggregate` rows carry a durable, monotonic integer `version`:

- **creation = 0** (the INSERT that creates `devops_incidents` writes
  `version = 0` and the in-memory aggregate stays at 0);
- **every successful update advances the stored version by exactly one**
  (one `version = version + 1` inside the same transaction as the
  business write — never two, never zero);
- **rejected or failed writes leave the stored version unchanged**, and
  the rejected in-memory aggregate's version is not advanced either.

There are no timestamps, UUIDs, or client-generated tokens acting as
versions, and no `force=True`-style bypass exists anywhere.

## 2. The correctness gate is the SQL predicate

Every ordinary aggregate write goes through
`PostgresIncidentRepositoryAdapter.save_incident`:

```sql
UPDATE devops_incidents
   SET <payload columns>, version = :expected + 1
 WHERE id = :id AND version = :expected;
```

- **rowcount == 1** → the writer was fresh; evidence re-insert and the
  commit proceed inside the same transaction.
- **rowcount == 0** → stale writer: a structured `incident.write_conflict`
  event is recorded, `IncidentConcurrencyConflict(incident_id,
  expected_version)` is raised, and the transaction rolls back **before**
  any evidence or proposal write — no partial state.

This is deliberately **not** a SELECT-compare-UPDATE and **not** an N+1
check: the database evaluates the predicate on the row itself, atomically.
On SQLite the single-writer file lock serializes writers; on PostgreSQL
the same predicate is evaluated under row-level locking/MVCC. The
guarantee is identical on both backends because it is the predicate that
decides, not the client.

Failure mapping (Invariant C — truthful conflicts):

| Layer | Behavior |
| --- | --- |
| domain/repository | `IncidentConcurrencyConflict` (incident id + expected version only; no SQL, no secrets) |
| REST | `409` with `{"error": "incident_concurrency_conflict", "incident_id": …, "expected_version": …}` |
| proposal generation | conflict re-raised as-is (not wrapped as a persistence failure) so the endpoint can 409 |
| approval / RCA save / execute | typed failure → `409` through the existing failure→HTTP map |

A conflict is never reported as `200` or `success=true`, and lifecycle
writes are never "reload and overwrite": there is no catch-conflict →
reload → retry helper anywhere in the incident write path.

## 3. Writes that touch the aggregate

Every `devops_incidents` write was audited; `version` applies to the
incident aggregate only (claims keep their own CAS state):

| Write | Version effect |
| --- | --- |
| `save_incident` (update branch) | `+1`, gated by `WHERE id AND version` |
| `save_incident` (insert branch) | stores `0`; requires `expected == 0`; concurrent insert → typed conflict (PK), evidence integrity errors are **not** disguised as conflicts |
| `claim_execution_lease` (proposals JSON changes) | separate `version + 1` statement **inside the same transaction** as the claim write |
| `finish_execution_lease` (terminal txn: proposal status + incident status promotion + claim FREE + evidence) | `version + 1` **once**, in the one transaction; a rejected terminal write returns `False` and rolls the whole transaction back |
| `persist_execution_progress` (heartbeat/stage) | claim-owned path: stage/lease CAS only, no aggregate version change (in-process cursor writes, documented in the lease tests) |

Execution lease/claim CAS is untouched: the claim predicate never
includes `version`, so the two CAS layers (aggregate freshness vs lease
ownership) cannot fight each other.

## 4. Migration (idempotent, no drop/recreate)

`create_all` alone is insufficient for an existing database, so the
adapter runs the smallest schema-evolution mechanism on startup —
`_ensure_version_column`:

1. inspect columns; if `version` exists → no-op;
2. otherwise `ALTER TABLE devops_incidents ADD COLUMN version INTEGER
   NOT NULL DEFAULT 0`;
3. on a concurrent-startup race (SQLite duplicate column / Postgres
   42701) re-inspect once, then fail loudly.

Tables are never dropped or recreated; proposals (incident-row JSON),
evidence rows, and execution claims are preserved byte-for-byte. Fresh
databases get the column from `create_all`; legacy databases get it from
the ALTER; reruns of either are no-ops. All three cases are tested
(`MigrationTests` in `incident_service/test_incident_concurrency.py`).

## 5. Races that are covered by real threads

Tests use `threading` + `threading.Barrier` (start synchronization) and
**no timing sleeps**:

- §17/§18 — four concurrent `save_incident` calls on the same snapshot:
  exactly one winner, three typed conflicts, loser evidence absent;
  two readers + one writer variant likewise.
- §21 — two concurrent legacy `POST /remediation` calls: one logical
  proposal, both callers converge on `proposal-{incident_id}` (or one
  typed conflict), orchestrator provider never constructed.
- §10 — two concurrent approvals of the same hash: the loser either
  observes `APPROVED` (idempotent-same, the pre-existing policy) or
  receives a typed conflict; exactly one durable approval either way.
- §11 — regeneration vs execution: with the claim taken first, a
  regeneration write commits (`+1`), then the execution terminal
  transaction still lands **as one unit** (status, claim FREE, evidence,
  `+1`) — or writes nothing at all. No torn terminal state exists in
  either interleaving.
- §7/§12 — stale regeneration / stale RCA-shaped writes racing approval:
  approval state survives; stale save raises.

SQLite serializes writers at the file lock; the CAS predicate is what
makes the outcome deterministic. PostgreSQL provides the same outcome
via row locks — this is a guarantee of the predicate, not of the thread
scheduler.

## 6. Deliberately out of scope (no silent inventions)

- No new migration framework (single explicit ALTER + `create_all`).
- No auto-reload-retry for lifecycle/security writes (masked concurrency
  is forbidden).
- No changes to sandbox, patch policy, hash identity, auth, or gateway
  behavior beyond mapping `IncidentConcurrencyConflict` to HTTP 409.
- `create_remediation` (compatibility shim) persists only through the
  same CAS save as every other writer — it has no privileged path.
