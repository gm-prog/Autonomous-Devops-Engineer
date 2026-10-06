# Phase 8.4.2-G.1 — Deterministic Operational Evidence Contract

**Status:** implemented and unit-verified. Not operationally executed against
live telemetry — see *Known limitations*.

This phase builds the **evidence substrate**: the typed, provenance-preserving
layer that turns raw operational observations into a single immutable,
reproducible artefact. It is the input a future reasoning layer will consume.

> The agent may reason over evidence, but it must never manufacture the
> evidence.

Nothing in this layer calls a model, and nothing in it is allowed to. The
correlation engine is ordinary deterministic code: the same inputs always
produce the same output, byte for byte, in any process, in any order.

---

## A. What exists

| Path | Lines | Role |
| --- | ---: | --- |
| `devops-ai-platform/shared_kernel/evidence/canonical.py` | 183 | canonical JSON, SHA-256, UTC rules |
| `devops-ai-platform/shared_kernel/evidence/identities.py` | 379 | repository / service / runtime / deployment identity |
| `devops-ai-platform/shared_kernel/evidence/model.py` | 914 | value objects, enums, limits, item, relationship, pack |
| `devops-ai-platform/shared_kernel/evidence/correlation.py` | 562 | the deterministic correlation engine |
| `devops-ai-platform/shared_kernel/evidence/adapters.py` | 573 | narrow source adapters (they never correlate) |
| `devops-ai-platform/shared_kernel/evidence/store.py` | 174 | write-once repository port + in-memory implementation |
| `devops-ai-platform/shared_kernel/evidence/replay.py` | 308 | capture and offline replay |
| `devops-ai-platform/api_gateway/routers/evidence.py` | 125 | three authenticated read-only endpoints |
| `devops-ai-platform/tests/test_operational_evidence_contract.py` | 1084 | domain, correlation, replay, persistence, adversarial |
| `devops-ai-platform/api_gateway/tests/test_evidence_plane.py` | 208 | API reads, auth boundary, absence of mutation |
| `devops-ai-platform/scripts/evidence_pack_fingerprint.py` | 138 | cross-process determinism fixture |
| `devops-ai-platform/scripts/evidence_assert_conflict.py` | 49 | CI guard: conflicts must survive, not resolve |

One cohesive module. No new service, no new database, no new auth mechanism,
no ORM model.

---

## B. Architecture

```
source systems          adapters              engine                pack              API
──────────────   →   ──────────────   →   ──────────────   →   ──────────   →   ──────────
incident svc         IncidentEvidence      Operational          EvidencePack      GET  /v1/incidents/{id}/evidence
deployment svc       Deployment…           Correlation          (immutable,       GET  /v1/evidence-packs/{id}
GitHub / Git         GitHub…               Engine               hashed)           GET  /v1/evidence/{id}
monitoring           Monitoring…           (pure function)
validation / E2E     Validation…
```

The four stages are deliberately separate and each is independently testable:

* **Ingestion** — an adapter reads one source and emits `EvidenceItem`s. An
  adapter may normalize and it may reject. It may **not** correlate, and it
  performs no I/O of its own; callers pass already-fetched records in.
* **Normalization** — identity parsing, UTC coercion, canonical form, limits.
* **Correlation** — a pure function `(incident_id, items, generated_at) →
  EvidencePack`. No clock read, no network, no database.
* **Persistence** — a write-once repository behind a port. Reads only.

Legacy `IncidentEvidence` rows are bridged by
`IncidentEvidenceSource.from_legacy_evidence()`, and deployment provenance
records by `DeploymentEvidenceSource.from_provenance_record()`, which calls the
existing `verify_provenance_record`. Neither existing type was modified.

---

## C. Schema

`EvidencePack` fields: `evidence_pack_id`, `incident_id`, `generated_at`,
`schema_version`, `correlation_policy_version`, `evidence_items[]`,
`relationships[]`, `summary`, `provenance`, `integrity`.

* schema version — `devops.operational-evidence/1`
* correlation policy version — `devops.correlation-policy/1`
* capture schema version — `devops.evidence-capture/1`

Controlled vocabularies, all finite and closed:

| Vocabulary | Members |
| --- | --- |
| `ObservationType` (12) | METRIC, LOG, TRACE, INCIDENT, DEPLOYMENT, GIT_COMMIT, GITHUB_EVENT, KUBERNETES_STATE, CONFIGURATION_CHANGE, REMEDIATION_HISTORY, HEALTH_CHECK, VALIDATION_RESULT |
| `EvidenceStatus` (7) | AVAILABLE, MISSING, UNAVAILABLE, NOT_REQUESTED, INVALID, CONFLICTING, STALE |
| `EvidenceStrength` (4) | DIRECT, DERIVED, CORRELATED, CONFLICTING |
| `RelationshipType` (10) | CAUSED_BY, PRECEDED, DEPLOYED_AS, GENERATED_BY, OBSERVED_ON, CORRELATES_WITH, DERIVED_FROM, VALIDATES, CONTRADICTS, AFFECTS |
| `CorrelationKeyType` (13) | incident_id, trace_id, span_id, request_id, deployment_id, workflow_run_id, commit_sha, repository, pod_uid, service.name, service.instance.id, environment, service.scope |
| `SourceType` (8) | monitoring, incident_service, deployment_service, github, git, kubernetes, e2e, database |
| `EvidenceErrorCode` (12) | INVALID_EVIDENCE, INVALID_PROVENANCE, INVALID_CORRELATION_KEY, INVALID_IDENTITY, CONFLICTING_EVIDENCE, STALE_EVIDENCE, EVIDENCE_TOO_LARGE, EVIDENCE_NOT_FOUND, PACK_NOT_FOUND, SCHEMA_VERSION_UNSUPPORTED, CORRELATION_POLICY_UNSUPPORTED, IMMUTABLE_EVIDENCE |

**Naming.** No field is called `data`, `info`, `metadata`, `context` or
`source`. Service identity uses OpenTelemetry attribute names
(`service.name`, `service.version`, `service.instance.id`,
`deployment.environment.name`) with no parallel `serviceName`/`svc_name`.
External identifiers live in `provenance.source_reference`, never loose in the
payload.

**Absence is typed.** `null` is not `"unknown"` and `""` is not absent —
`DeploymentIdentity(source_sha=None)` means *not asserted*, and an empty string
is rejected rather than stored. `MISSING` (looked for, not there),
`UNAVAILABLE` (could not be queried) and `NOT_REQUESTED` (never asked) are
three different facts. A 404 from a source never becomes "does not exist".

**Temporal.** `observed_at` (when it happened) and `collected_at` (when we
learned of it) are separate fields. Naive datetimes are rejected at the
boundary — never assumed to be UTC. Everything is stored and serialized in UTC
as `%Y-%m-%dT%H:%M:%S.%fZ`.

---

## D. Correlation

Correlation is deterministic interpretation of facts, never invention. Each
item is bound to the incident anchor by exactly **one** rule — the strongest
that matches:

| Precedence | Rule | Binds on | Edge |
| ---: | --- | --- | --- |
| 1 | `R1-incident-binding` | exact `incident_id` | CORRELATES_WITH |
| 2 | `R2-trace-binding` | shared `trace_id` / `request_id` | CORRELATES_WITH |
| 3 | `R3-deployment-binding` | same `deployment_id` | DEPLOYED_AS / CORRELATES_WITH |
| 4 | `R4-service-environment-binding` | canonical `service.scope` (`name@environment`) | CORRELATES_WITH |
| 5 | `R5-repository-commit-binding` | repository + commit SHA | CORRELATES_WITH |
| 6 | `R6-temporal-proximity` | bounded window, same environment | PRECEDED / CORRELATES_WITH, `temporal=True` |

Two supporting rules: `R3a-deployment-grouping` links telemetry to the
deployment that emitted it (GENERATED_BY), and `C1-deployment-identity-conflict`
detects contradictory claims.

Non-negotiables enforced in code and in tests:

* **Temporal proximity is never causation.** R6 edges carry `temporal=True`
  and use `PRECEDED`, not `CAUSED_BY`. Constructing a `CAUSED_BY` relationship
  with `temporal=True` raises. Within the 2 s skew tolerance the engine emits
  `CORRELATES_WITH` and the basis says *no ordering is claimed*.
* **Environment never merges.** `checkout@production` and `checkout@staging`
  are different services. Staging evidence is retained in the pack and left
  uncorrelated rather than quietly folded into a production incident.
* **Every relationship is explained.** `basis` and `rule_id` are mandatory.
  There are no probabilistic confidence scores; strength is one of four typed
  values.
* **Ordering is irrelevant.** Items are de-duplicated by `evidence_id`, sorted
  canonically, and relationships are emitted in a canonical order. All 120
  permutations of the five-item fixture produce the identical pack hash.
* **Conflicts are preserved, never resolved.** Two deployment records claiming
  different `source_sha` for one `deployment_id` produce a `CONTRADICTS`
  relationship, `summary.pack_status = "CONFLICTING"`, and
  `resolution: "NONE - both observations are preserved"`. Both items stay in
  the pack. There is no last-write-wins path.
* **Staleness is reported, not applied.** `summary.freshness` and
  `summary.stale_evidence_ids` record it; the stored observation is never
  rewritten.

Complexity is kept linear by keyed indexes and a bounded window
(`[anchor − 30 min, anchor + 15 min]`, inclusive both ends) with a
`max_bucket_pairs` cap of 10 000 — no all-pairs comparison.

---

## E. Integrity

Canonical form is `json / sorted keys / compact separators / ascii`, then
SHA-256.

* Keys sorted by Unicode code point; strings NFC-normalized; `null` retained
  and distinct from absent; integral floats never folded into ints; NaN and
  Inf have no canonical form and are rejected; bytes are rejected rather than
  guessed; non-string keys rejected; maximum nesting depth 32.
* `content_hash` covers the whole claim — observation type, observed_at,
  status, strength, payload, incident id, service / deployment / resource
  identity, correlation keys, and the content-bearing provenance fields. It
  deliberately excludes the *circumstances of collection* (`collected_at`,
  `provenance.retrieved_at`) so that re-collecting the same observation is
  idempotent.
* `evidence_id` = `ev-<sha256(source_system + source_reference + observed_at +
  content_hash)[:32]>`.
* `pack_hash` = SHA-256 over schema version, policy version, incident id,
  items, relationships and summary. **`generated_at` is excluded on purpose** —
  a pack regenerated or replayed later must hash identically.
* `evidence_pack_id` = `pack-<pack_hash[:32]>`.

Nothing is ever hashed from `repr()`, and no hash depends on insertion order.

Supplying a `content_hash` or `evidence_id` that does not match the derivation
is rejected with `INVALID_EVIDENCE` — a caller cannot assert an identity the
content does not support.

---

## F. Replay

`capture_inputs()` writes a self-contained bundle: capture schema version,
policy version, incident id, `generated_at`, every raw item, and a
`capture_hash` over the lot. `replay_capture()` verifies that hash, rehydrates
each item through the same validation path as live ingestion, and re-runs the
engine.

Replay is a pure function with zero I/O — the test suite monkeypatches
`socket.socket` and `socket.create_connection` to prove it. A tampered bundle
fails the capture-hash check; an unknown schema or policy version is refused
with `SCHEMA_VERSION_UNSUPPORTED` / `CORRELATION_POLICY_UNSUPPORTED` rather
than being best-effort interpreted.

Measured on the §53 acceptance fixture:

```
pack_hash        8a66e8862bcc3e1033c3cf4e67b49e0d5f945a791fdda0ff74b4bf65d6f0f7d8
evidence_pack_id pack-8a66e8862bcc3e1033c3cf4e67b49e0d
items 5   relationships 6   status COHERENT   replay matches: yes
```

With the contradictory second deployment SHA added:

```
pack_hash        a8cd28036735f443cbb91d88d9ca2b7e8f1cce84caeb6f2e778fdf68000375df
evidence_pack_id pack-a8cd28036735f443cbb91d88d9ca2b7e
items 6   status CONFLICTING   both SHAs preserved   replay matches: yes
```

Both hashes are stable across `PYTHONHASHSEED` 0, 1 and 12345 in separate
interpreter processes. CI re-checks this on every run.

---

## G. Security

Evidence is **untrusted input**. Log lines, commit messages and Kubernetes
labels are attacker-influenceable, so the layer treats them as inert bytes:

* Stored as data. Never executed, never `eval`'d, never interpolated into an
  instruction template, never interpreted as policy or configuration. A static
  test parses every module's AST and fails on `eval`, `exec`, `compile`,
  `__import__`, `os.system`, `subprocess.*` and attribute lookups resolved from
  runtime data.
* A pack grants no capability: no `tools`, `permissions`, `allowed_actions`,
  `exec` or `command` field exists, and the serialized pack is asserted to
  contain no `authorization`, `bearer`, `secret`, `token` or `password`.
* Explicit bounds, enforced with structured rejection rather than silent
  truncation: payload 256 KiB, string 32 KiB, depth 16, 2 000 items per pack,
  20 000 relationships, 32 correlation keys per item.
* A fake SHA such as `"trust-me"` is rejected at identity construction. SHAs
  must be 40 hex characters; digests must be `sha256:<64 hex>`.
* Repository identity normalizes case, `.git`, trailing slash and whitespace
  while preserving the original string, so
  `gm-prog/Autonomous-Devops-Engineer` and `gm-prog/ares-e2e-fixture` can never
  be conflated.
* No vendor connector ships in this phase — interfaces only. No credential,
  no live endpoint, no network import in the package.
* Errors are machine-readable (`error_code`, `message`, `details`) and map to
  precise status codes. Predictable validation failures never surface as a
  generic 500, and no traceback or internal path is returned.

---

## H. API

Three authenticated reads under the existing gateway:

```
GET /v1/incidents/{incident_id}/evidence
GET /v1/evidence-packs/{evidence_pack_id}
GET /v1/evidence/{evidence_id}
```

Every route depends on the platform's existing `verify_token` (HS256 JWT) and
the existing rate limiter. No new authentication mechanism, nothing public.

**There is no write surface.** `POST`, `PUT`, `PATCH` and `DELETE` are not
registered, so they return 405 — history is not "protected by a role", it is
unreachable. A correction is a new observation: it hashes differently and
therefore receives a new id, leaving the original intact. A test asserts every
registered route on this router is `GET`-only.

| Condition | Status | `error_code` |
| --- | ---: | --- |
| unknown pack | 404 | PACK_NOT_FOUND |
| unknown evidence | 404 | EVIDENCE_NOT_FOUND |
| unknown incident | 200 | — (an empty set, not an error) |
| invalid evidence / provenance / key / identity | 422 | INVALID_* |
| over a declared limit | 413 | EVIDENCE_TOO_LARGE |
| conflict / stale / immutable / unsupported version | 409 | … |

`GET /v1/incidents/{id}/evidence` returns an empty set for an unknown
incident rather than 404, because "we hold no evidence" is not the same claim
as "this incident never existed".

---

## I. Observability

Six counters are registered alongside the existing Prometheus metrics, with
bounded label vocabularies only — never per-incident or per-evidence ids:

`evidence_ingested_total`, `evidence_rejected_total`, `evidence_conflict_total`,
`evidence_correlation_total`, `evidence_pack_generation_total`,
`evidence_replay_total`.

---

## J. CI

A seventh job, `operational-evidence`, runs the full contract suite offline
with no vendor or production credential, then independently verifies
cross-process determinism by running the fingerprint fixture under three hash
seeds and asserting a single distinct hash, and runs
`evidence_assert_conflict.py` so a future change that "helpfully" resolves a
contradiction fails the build. Results are published as a step summary and an
annotation, because job logs are not readable through the API on this
installation.

---

## K. Known limitations

These are real and deliberately not hidden:

1. **Persistence is in-memory only.** `InMemoryEvidenceRepository` satisfies
   the port and is write-once, but packs do not survive a process restart. A
   Postgres adapter behind the same port is deferred; no schema was added in
   this phase, by design.
2. **No live source connectors.** Adapters accept already-fetched records.
   Nothing in this phase talks to Prometheus, Loki, Tempo, the GitHub API or a
   Kubernetes API server.
3. **Not operationally executed.** Everything here is verified by unit,
   correlation, replay, persistence, API and adversarial tests against literal
   fixtures. No pack has been generated from live production telemetry. Tests
   passing is not the same as operational execution.
4. **Conflict detection covers deployment identity.** `C1` detects
   contradictory `source_sha` for one `deployment_id`. Other contradiction
   classes (disagreeing metric values from two collectors, for example) are not
   yet modelled.
5. **Retention is stated, not implemented.** Evidence is write-once and
   append-only; no retention, archival or compaction machinery exists, and none
   was built.
6. **Single-process assumptions.** The in-memory repository is not
   thread-safe and offers no concurrency guarantees.

---

## L. Next phase boundary

**G.1 builds deterministic evidence. It does not implement autonomous agent
reasoning.**

No LLM, agent, MCP or A2A component exists in this layer, and the pack contains
no `agent_reasoning`, `model_confidence` or `chain_of_thought` field — asserted
by test. A future reasoning phase may consume packs; it may not produce them.
