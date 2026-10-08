# Phase 8.7-B.2 — Trusted traffic mutation provider

Status: implemented, exercised against a disposable Kind + Gateway API +
Envoy Gateway cluster in CI. This is **not a production** rollout mechanism and
it is not a claim that any traffic shift is safe; it is the mechanism, its
refusals, and the evidence for both.

The provider is the first thing in this repository that is allowed to *change*
live traffic. Everything below is written around that one risk: how an
invalid, stale, ambiguous, duplicated, unauthorized or unverifiable request is
prevented from becoming a successful mutation, and how a reader can tell from
the evidence alone which of those it was.

---

## 1. Scope

Added by this phase (all under `devops-ai-platform/`):

| Artifact | What it is |
| --- | --- |
| `incident_service/infrastructure/traffic_mutation/trusted_mutation_provider.py` | `TrustedTrafficMutationProvider`: the `TrafficMutationPort` implementation, the attempt registry, the authority/precondition rules, the classification and the evidence records |
| `incident_service/infrastructure/traffic_mutation/kubernetes_mutation_client.py` | `KubernetesMutationClient`: the single bounded write, and the only process spawner in the package |
| `incident_service/infrastructure/traffic_mutation/__init__.py` | the package's explicit public surface |
| `tests/test_phase_8_7_b_2_trusted_traffic_mutation_provider.py` | the safety-probe battery, the explicit contract tests, and the source-mutation controls |
| `tests/test_phase_8_7_b_2_driver_control_flow.py` | runs the *real* E2E driver against a stub cluster and requires each weakened variant to turn red |
| `e2e/traffic_mutation_kind_e2e.py` | the live driver: APPLY, ROLLBACK, the refusals, the race, two competitors, and the data-plane cross-check |
| `.github/workflows/ci.yml` → `kubernetes-traffic-mutation-e2e` | the job that runs the above on real Kind |
| this document | the design, the vocabulary, and the limits |

Deliberately unchanged: the Phase 8.7-A boundary
(`traffic_mutation_boundary.py`) including `UnavailableTrafficMutationProvider`
as the default, the Phase 8.7-B.1 observer and read client, the Phase 8.7-B.0
topology fixture, `k8s/deployment.yaml`, `k8s/operator.py`, `k8s/progressive/*`,
the rollout state machine, and the approval policy.

The write path lives in `infrastructure/traffic_mutation/`, **not** in
`infrastructure/traffic/`: B.1's read-only guard allowlists exactly one file in
that package (`kubernetes_read_client.py`), and keeping the writer out of it
keeps "this package can only read" mechanically true rather than merely
documented.

## 2. Architecture — one interpretation, one write

```
approved TrafficMutationRequest (Phase 8.7-A; exact authority, derived digest)
            │
            ▼
 1. execution claim        duplicate / concurrent attempt ─────────► REFUSE
            │
            ▼
 2. fresh B.1 observation  UNKNOWN / CONFLICT / unbound / wrong
            │              target / stale request ────────────────► REFUSE
            ▼  KNOWN + trusted identity + controller authority
 3. authority + precondition (does this transition start here?)
            │              live ≠ authorized start ───────────────► REFUSE
            ▼
 4. build the exact authorized change (two weights, nothing else)
            │
            ▼
 5. exactly ONE bounded compare-and-set write
            │
            ▼
 6. fresh post observation (the only thing that can verify anything)
            │              unavailable / third state / unchanged ───► no claim
            ▼  remote == the state this operation completes
 7. TrafficMutationResult(verified=True) + machine-readable evidence record
```

The provider never re-implements what B.1 already interprets. Track identity,
endpoint disjointness, configured share, controller acceptance, ResolvedRefs,
the binding rule and the findings all come from
`KubernetesTrafficObserver.inspect_detailed(run_id, sha)`. The provider adds
exactly two things on top of that: a **stricter authority rule** (§3) and the
write itself.

## 3. Authority model

`metadata.generation` is the revision of the route **spec**. A controller
`observedGeneration` is how far the controller has *processed* that spec.
`Accepted=True` says the controller accepted the route; `ResolvedRefs=True`
says every `backendRef` resolves to an existing Service.

Mutation authority requires all of:

* the fresh observation is `KNOWN`;
* `Accepted is True` **and** `ResolvedRefs is True`;
* `route.generation is not None` and
  `controller_observed_generation == route.generation` — the controller must
  have observed the *exact current* generation of the route being changed;
* the observation is bound to this deployment run and source revision;
* the observed identities are the requested targets (§4);
* the request is fresh (see §5) and its run/SHA are the host-owned ones when
  the provider was configured with them.

Everything else is `refused:authority`. A route that is still reconciling, or
whose status predates its own spec, is not authority to write.

The **postcondition deliberately does not require the controller to have
caught up with the write.** The controller's rendered state lags the spec by
construction; requiring it after the write would either fail every honest
attempt or force a wait-and-hope loop. What the postcondition requires is that
the *spec* — the thing the provider changed — is observed exactly, and the
controller facts are recorded beside it in the evidence rather than used as
the success criterion.

## 4. Target binding

A target is `{namespace}/service/{name}`, and it is never inferred from a
name's spelling. The request carries `stable_target`/`canary_target`; the
observation carries `stable_identity`/`canary_identity` **and** per-track
`TargetFacts` whose own `identity` property renders the same string from the
live Service's namespace and name.

Both renderings are checked against the request, and against each other
(`refused:authority` on any mismatch). A request that names a backend the live
topology does not have — or that renames an existing one, or presents a bare
Service name — is a **security-boundary refusal**, never a "close enough"
match:

* `the observed stable identity is 'ares-traffic/service/other', not the
  requested 'ares-traffic/service/ares-stable'`;
* `the live canary target is ..., not the requested ...`;
* `the observation is internally inconsistent: its reported stable identity
  differs from its stable target facts`.

The write itself is then built from `route.backends` (the trusted
track→name mapping) and cross-checked against a fresh read of the same route
(§7).

## 5. Precondition

The request's own `observed_at` has an age: `max_request_age_seconds = 300`
and `max_clock_skew_seconds = 60` by default. A decision built on an
observation older than that is not this request, however convenient the live
state looks.

Then the live state must be the state this operation is authorized **from**:

* `APPLY`: live canary share == `request.expected_current_percentage`;
* `ROLLBACK`: live canary share == `request.requested_percentage` (§9).

The live share comes from the B.1 observation, never from the request:
`configured_percentage` must equal `observation.observed_percentage`, i.e. the
reported percentage must be the exact configured share of the live weights. A
mismatch is `refused:authority` — the observation is internally inconsistent
and is treated as unusable rather than averaged away.

## 6. The Mutation boundary: what APPLY may do

`APPLY` performs one forward transition, verified at
`request.requested_percentage`. There is exactly one operation the package can
express:

* **weights, denominator 100**: canary percentage `p` maps to stable
  `100 - p` and canary `p` by exact integer arithmetic. There is no rounding
  step, no float authority, and no `percentage_from_weights` result that is
  not an exact share. The only division in the package is the exact
  `canary / (stable + canary) * 100` check;
* **the route's `spec.rules[0].backendRefs[i].weight` fields, and nothing
  else**. Not the names, not the ports, not the matches, not annotations, not
  the parentRefs;
* the route is the host-owned one the provider was constructed with
  (`route_name`, `namespace`); the request cannot name a resource, a verb, a
  GVR, a namespace, a JSONPath, a patch document or a file path.

A route with anything other than exactly one weighted rule with exactly two
`backendRefs` is `refused:conflict` (ambiguous layout) — the provider does not
guess which rule "the" split is.

The **weights are not a percentage**. The route stores a proportional weight;
the request authorizes a percentage; the mapping between them is the exact
arithmetic above. Nothing in the provider compares a weight to a percentage,
and the data-plane check in §15 is statistical on purpose.

## 7. The write itself: one bounded compare-and-set

The client has one public write method and one mutating verb:

```
kubectl patch httproute [--context C] [--kubeconfig P] <route> -n <ns> \
  --type=json -p <json> --request-timeout=<n>s
```

`--type=json` means RFC 6902, and the patch document is built from typed
values only:

1. `test` on `/metadata/resourceVersion` — the compare-and-set: if anything
   moved the route between the observation and the write, the API server
   rejects the *whole* patch. A lost race is a rejection, never a stale write;
2. `test` on each changed backend's `/name` and `/weight` — a patch built
   against a different layout is rejected rather than applied to the wrong
   slot;
3. exactly two `replace` operations, on those weights only.

Seven operations, always. There is no `run(argv)`/`run_kubectl`/`execute`/
`shell`/`patch(raw_payload)` anywhere in the package: no public function
accepts an argv, a verb, a resource, a payload or a path expression; there is
no shell, no `shell=True` and no command string; the process is spawned once,
in `KubernetesMutationClient.apply_weight_mutation`, with a host-built list
argv. That call site is registered in the execution-boundary audit
(`RepositoryExecutionBoundaryAuditTests.ALLOWED["subprocess."]`).

The attempt is classified from the API server's own answer
(`accepted` / `rejected` / `unknown`); the return code alone never means
"the mutation happened". One attempt per operation: a timeout is **not**
retried here, and the provider refuses if the client ever reports more than
one attempt for one authorized transition.

## 8. Postcondition

Verification is a remote-state claim, not a causality claim. `verified=True`
means exactly what the frozen Phase 8.7-A contract says: the fresh
post-mutation observation equals the state this operation completes. Command
success is never verification, and a provider-side "success" variable never
substitutes for the postcondition.

Whether *this* call produced that state is a separate fact (`causality` in the
evidence):

| situation | classification | causality |
| --- | --- | --- |
| write accepted, route observed at the target | `verified:write-accepted-and-observed` | `this-write-accepted-and-observed` |
| answer lost, route observed at the target | `verified:remote-state-after-unknown-attempt` | `observed-desired-after-unknown-attempt` |
| write refused, route observed at the target anyway | `refused:write-refused-by-server` (**not** verified) | `this-write-refused-by-server` |
| route still at the pre state | `failed:write-did-not-change-the-state` | `this-write-did-not-change-the-state` |
| route at a third state | `refused:conflict` | (as above, still recorded) |
| post-observation unavailable | `unverified:postcondition-not-established` | (as above) |

An accepted write must also show a strictly greater route generation, and an
unknown attempt may not show a lower one; an observation that contradicts the
write's own answer is refused rather than believed.

## 9. ROLLBACK

`ROLLBACK` completes the **same approved forward transition**, from the other
end:

* it is only valid when the live state is the state that transition reached
  (`request.requested_percentage`);
* it mutates back to `request.expected_current_percentage`;
* it verifies at that derived target — never at a caller-supplied one. There
  is no `rollback_to_percentage`, and no public function on either module
  takes a rollback target: the target is derived from the request, and the
  operation only participates in the internal assertion that the derived
  target is the state this operation completes.

It is therefore never reachable as a smaller `apply()`: the port has two
distinct members, `apply()` is forward-only, and `_build_mutation` asserts
that the target it built is the state the *operation* completes before the
write exists at all.

## 10. Idempotency

A request's digest is its logical mutation identity: a SHA-256 over the
canonical request payload, derived by the boundary (`request.digest()`), never
supplied by a caller. The attempt registry is keyed by
`(digest, operation)`:

* **first APPLY**: claimed, observed, written, verified, finished;
* **duplicate APPLY after success**: the registry holds the completed record
  for this digest, so the provider returns
  `already-applied:idempotent-replay` with `causality=no-attempt-in-this-call`
  — no write, no new claim, and the evidence says it was a replay;
* **already at the target with no record of this provider performing it**:
  `already-applied:unattributed`. It is reported, never credited: the live
  state may have been reached by anyone, so the provider does not claim it;
* **stale APPLY / a different digest**: no replay path exists; the
  precondition refuses it (`refused:precondition`);
* **competing APPLYs of the same digest**: one claim holder, the others are
  `refused:concurrent-claim` before any cluster access.

A refusal never leaves the digest claimed: every non-success path releases the
claim (`finish(..., state="refused")`), so a corrected retry is possible and a
crash cannot wedge the digest. Claims expire after 120 s
(`InMemoryMutationAttemptRegistry(claim_ttl_seconds=120)`) — deliberately
shorter than the 300 s freshness bound, so a claim can never outlive the
decision it protects.

## 11. Concurrency

The repository's model is at-least-once delivery plus idempotency, CAS and
leases, never exactly-once
(`docs/phase-8-concurrency-model.md`, `execution_claims`). This phase adds no
new lock and no new state store; it composes two existing mechanisms:

* an **in-process attempt registry** (the `MutationAttemptRegistry` Protocol;
  `InMemoryMutationAttemptRegistry` is the shipped implementation) for claims
  and replays within one provider instance, with a TTL;
* a **server-side compare-and-set** in the write itself, which is what makes
  concurrency safe *across* processes: two providers that both read the route
  and both write can only have one write accepted, because the second one's
  `resourceVersion` test fails.

The E2E proves both: two providers race the identical request and exactly one
verifies (the loser records `refused:concurrent-claim` or a rejected write
whose `causality` is `this-write-refused-by-server`), and a competing actor
that changes the route between the observation and the write keeps its own
state — the patch is rejected and the other actor's change survives.

## 12. Unknown outcomes

A lost answer is never resolved by trying again: the first patch may have
landed. The provider distinguishes:

* **unknown, landed**: a fresh observation shows the target state →
  `verified:remote-state-after-unknown-attempt`, with the attempt's own
  `unknown` outcome recorded beside it and no fabricated external operation
  id;
* **unknown, not landed**: a fresh observation shows the pre state →
  `failed:write-did-not-change-the-state`;
* **unknown, third state**: `refused:conflict` — nothing is attributed to this
  call and the state is reported as it is;
* **observation unavailable**: `unverified:postcondition-not-established`.

`external_operation_id` is only ever what the command itself reported; when
the command did not answer, the field stays empty.

## 13. Evidence

Every call — success or refusal — appends one machine-readable record
(`traffic-mutation-evidence-v1`, `evidence_to_json()` = sorted keys and a
trailing newline). A record separates the facts that are usually collapsed
into one boolean:

* **request identity**: the full request payload (run, SHA, gate evaluation
  id, intent id, targets, percentages, observed time) and its derived digest;
* **operation** (`APPLY`/`ROLLBACK`), **classification** and **causality**;
* **concurrency**: registry, claim id, claim state, whether this was a replay,
  and how many write attempts this call made;
* **pre** and **post** observation summaries: status, percentage, the
  configured share and its exact weight pair, both identities, binding,
  endpoint disjointness, collection time, route name/namespace/generation/
  weights/backends/controller `observedGeneration`, controller
  `accepted`/`resolvedRefs`, the per-track target identities, and bounded
  findings;
* **mutation**: the resource version the write was conditioned on and the
  exact (index, name, expected weight, new weight) changes;
* **attempt**: state, bounded detail, the command's own reported operation id
  and resource version, duration;
* **verification**: expected percentage, observed percentage, `verified`,
  reason;
* **target/remote percentage** and a bounded, redacted reason
  (`MAX_REASON_LENGTH = 400`, at most `MAX_FINDINGS_IN_EVIDENCE = 4`
  findings).

`attempted`, `accepted-by-the-client`, `reported-by-the-command`,
`observed-remotely` and `verified` are distinct fields and are never merged.
The live driver seals the *run's* evidence with the same provenance helper the
other phases use (`e2e/evidence_provenance.py`): deterministic JSON, a SHA-256
sidecar next to the artifact, and the workflow run/job identity inside.

Nothing in the record is fabricated and nothing is secret: no tokens, no
kubeconfig, no credentials — the provider never reads one, and free text goes
through B.1's `redact()` (which also masks file paths) before it is stored.

## 14. Security boundary

* **no arbitrary Kubernetes execution**: one verb (`patch`), one resource
  (`httproute`), one shape of payload; the forbidden-subcommand list
  (`delete`, `create`, `replace`, `edit`, `exec`, `scale`, `rollout`, …) is
  checked against every argv element before the process is spawned;
* **no caller-controlled execution**: no public function takes an argv, a
  command string, a GVR, a namespace, a JSONPath, a patch payload or a path;
* **validated identifiers**: namespace/name/context/label go through the B.1
  read client's own validators, and reserved namespaces are refused;
* **no approval bypass**: the provider never manufactures a
  `gate_evaluation_id`, an `intent_id`, a `deployment_run_id`, a `source_sha`
  or a target. It carries the request's identity verbatim (the tests assert
  that no such literal, no `uuid4`, no `hashlib` and no `getenv` appears in
  the package's executable source), and the request itself was constructed by
  the boundary from a presented intent;
* **fail closed**: an unavailable provider still raises
  `TrafficMutationProviderUnavailable`; a malformed request object is the only
  thing that raises; every other non-success is a truthful
  `verified=False` result with a reason;
* **the contracts are unchanged**: `TrafficMutationPort` still has exactly
  `apply`/`rollback`, `TrafficControllerPort` still has exactly
  `inspect`/`plan`, and no endpoint accepts a hand-built mutation request.

Two independent backstops also hold: the frozen Phase 8.7-A result contract
refuses to construct a `verified=True` result whose remote state is not the
operation's own target, and the structural guards assert that the Phase 8.7-A
boundary module still ships no provider implementation.

## 15. Live E2E evidence

`e2e/traffic_mutation_kind_e2e.py` runs on a disposable Kind cluster with the
pinned Gateway API CRDs and Envoy Gateway, against the committed B.0 topology
fixture (`k8s/progressive/`, 95/5). It performs, in order:

1. preconditions: pinned commit, pinned artifacts (checked against
   `e2e/pinned-traffic-topology.txt`), a live Kind control plane, its real
   server version, two *genuinely distinct* workload images, the pinned
   controller stack, the applied topology, readiness, and a first
   application-side observation of the 95/5 state by the shipped provider;
2. **APPLY 5% → 25%** through the shipped provider, then the driver's own
   read of the route (weights and `resourceVersion`), then the process's own
   accounting (`attempts == 1`, `verified`), then a **statistical** data-plane
   cross-check: 500 real requests through Envoy, which must be ≈25 % canary
   within the B.0 tolerance — never an exact figure, because the weights are
   proportional, not a percentage;
3. the duplicate: re-presenting the identical request must write nothing,
   change no `resourceVersion`, and report `already-applied:idempotent-replay`;
4. a fresh provider call against the already-applied state must refuse
   (`already-applied:unattributed`);
5. **ROLLBACK 25% → 5%** through the shipped provider, verified at 5 %, with
   its own data-plane cross-check;
6. refusals, each one proving *three* things — the provider refused, the write
   was never attempted, and the hazard was really present while the route's
   weights and `resourceVersion` stayed untouched: stale precondition (a
   request authorized from 5 % presented while the live route is 50/50), a
   wrong target identity, an unresolvable `backendRef`, an ambiguous layout
   (two weighted rules) and all-zero weights;
7. the compare-and-set: another actor writes between the observation and the
   write; the patch must be rejected and the other actor's state must survive;
8. two providers racing the identical request: exactly one verified mutation;
9. the final state: 95/5 again, observed by the application.

The driver's own patches (proof states, the competing actor, the injected
layout) are **harness control**, recorded separately in the evidence under
`driver_state_changes`; every APPLY/ROLLBACK under test is performed by the
application's provider. The evidence is sealed to
`traffic-mutation-e2e.json` (+ `.sha256`) with the cluster, controller and
image identities, every check, the provider's own records, and the run's
provenance.

CI job: `kubernetes-traffic-mutation-e2e` ("Phase 8.7-B.2 trusted traffic
mutation E2E"). It first runs the two B.2 test modules on the runner, then
builds and loads its own workload/sampler images, runs the driver with
`--deployment-run-id "$GITHUB_RUN_ID" --expected-commit "$GITHUB_SHA"`, mirrors
the driver's output and every failure into the step summary and `::error`
annotations, publishes the evidence and its digest, and **always** tears the
cluster down and uploads the artifact. No step is optional, none swallows a
failure, and a skipped E2E is never treated as proof.

## 16. Tests

* **Safety probes** (`SAFETY_PROBES`, 36 probes): each probe drives the
  shipped modules against a cluster-shaped fixture and returns a complaint
  when the safety property breaks. Every probe asserts the *danger is
  present* (the fixture really holds a stale state, an unaccepted route, a
  moved route, …) as well as the refusal, so a probe cannot pass vacuously.
* **Explicit contract tests**: weight arithmetic and the denominator, the
  request boundary (only a non-`TrafficMutationRequest` raises; the digest is
  derived, never supplied; the result binds the exact request and target),
  preconditions, authority, apply, rollback, idempotency, concurrency,
  unknown outcomes, evidence, the closed client surface, the package's public
  surface, the execution-boundary registration, the docs and the CI job.
* **Source-mutation controls** (`SourceMutationControlTests`): ten controls
  rewrite the shipped source in memory (drop the authority gate, drop the
  identity checks, remove the compare-and-set tests, make the client retry an
  unknown answer, coerce the weight exactness by rounding, ignore the claim,
  drop the controller `observedGeneration` check, weaken the postcondition,
  remove the generation guard, …), run the probe battery against the mutant,
  and require at least one *named* probe to break. A control that breaks
  nothing fails the suite: it means the probes do not bite.
* **Driver control-flow tests** (`test_phase_8_7_b_2_driver_control_flow.py`):
  run the real driver against a stub cluster in a healthy world (all checks
  pass, exactly the expected provider writes) and in five weakened worlds
  (a provider that never writes, an observer that cannot see the change, a
  client with no compare-and-set, a data plane that disagrees, a client that
  writes twice) — each must turn the run red at the intended check.

Run them with:

```
cd devops-ai-platform
PYTHONPATH=. python -m pytest -q tests/test_phase_8_7_b_2_trusted_traffic_mutation_provider.py \
                                     tests/test_phase_8_7_b_2_driver_control_flow.py
```

## 17. Limitations

* **Not a production rollout mechanism.** The live proof is a disposable Kind
  cluster with a single-node control plane, one Gateway, one HTTPRoute, two
  backend Services and a synthetic sampler. It proves the mechanism, not
  capacity, not a multi-cluster or mesh deployment, not a real ingress path.
* **Traffic safety is not proven.** Moving from 5 % to 25 % says nothing about
  whether 25 % is a safe amount of traffic; the gate evaluation that authorizes
  it is a different phase.
* **The registry is in-process.** The shipped `InMemoryMutationAttemptRegistry`
  protects one provider instance and the CAS protects across processes; a
  crash between the write and the record leaves the digest claimed until its
  120 s TTL expires, and the *next* call resolves the state by re-observing
  (never by replaying).
* **Statistical data-plane evidence has a tolerance.** The cross-check is 500
  samples at the B.0 tolerance (4σ); it can, rarely, miss a small real
  deviation and it will, rarely, fail on an unlucky run. It is evidence about
  proportions, never an exact assertion.
* **The controller's rendered state lags.** Verification is about the route
  spec, which is what this provider changes; the evidence records the
  controller facts, but the provider does not wait for the data plane.
* **The E2E is single-run.** A green run is proof that the mechanism worked in
  that environment at that SHA, not a statement about every environment, and
  the numbers in the phase report come from the CI run's own evidence, never
  from a local run.

## 18. Run record

The live proof for this phase is the run of this branch whose head is the
commit under test: job `kubernetes-traffic-mutation-e2e`, artifact
`traffic-mutation-e2e-evidence` (`traffic-mutation-e2e.json` and its
`.sha256`). The phase report quotes that run's identifiers, the observed
percentages, the data-plane cross-check, the refusal classifications and the
artifact digest directly from the run. Nothing in the report is derived from a
local test run, the run's evidence file is the authoritative record, and the
identifiers are deliberately not hard-coded here — a document cannot contain
the hash of the run that publishes it.

Two facts about this phase's CI history are worth stating plainly, because a
reader comparing runs will see them: the first push of this phase failed the
job before any cluster work, because `pytest` is not in `requirements.txt` and
the job's own safety-control step could not start; the next commit installs it
the way the existing `platform-tests` job does, changed nothing else, and the
job has run the full live sequence since. A skipped live step is never treated
as proof of anything.

