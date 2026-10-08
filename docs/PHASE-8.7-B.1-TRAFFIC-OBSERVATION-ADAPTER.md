# Phase 8.7-B.1 — Read-only traffic observation adapter

Status: implemented. The live proof runs in the dedicated CI job
`Phase 8.7-B.1 traffic observation E2E`, which brings up a disposable Kind
cluster, installs the pinned Gateway API/Envoy Gateway stack and observes
the live topology through the real provider; the sealed evidence artifact
of that job is the authority, not this document. This phase is not
complete until that job is green for the commit under test.

Predecessors: `docs/PHASE-8.7-A-TRAFFIC-MUTATION-BOUNDARY.md` (the mutation
boundary), `docs/PHASE-8.7-B.0-WEIGHTED-TRAFFIC-TOPOLOGY.md` (the weighted
Gateway API topology this phase observes).

## 1. Objective

Phase 8.7-B.0 proved that a real Envoy Gateway honours the committed
`ares-traffic` topology's weights. B.1 makes that state **observable by the
application** — read-only, through the boundary the repository already has
(`TrafficControllerPort` in `incident_service/application/services/rollout_plan_service.py`),
so `RolloutPlanService` can plan against what the cluster actually says
instead of against an assumption.

The objective is deliberately narrow: *observe*, never *change*. The
application still cannot mutate traffic in any way.

## 2. Architecture

Two new modules, one responsibility each:

| module | responsibility |
| --- | --- |
| `incident_service/infrastructure/traffic/kubernetes_read_client.py` | the closed read-only operation set and the client that executes it |
| `incident_service/infrastructure/traffic/gateway_api_observer.py` | translates those reads into `ObservedTrafficState` through `TrafficControllerPort` |

```
Kubernetes API server
        │  (read-only, closed operation set: get http_route|service|endpoint_slices|pods|deployments)
        ▼
KubectlReadClient  ──►  GatewayApiObserver.inspect()  ──►  ObservedTrafficState
        │                        │
        │                        └──►  TrafficControllerPort.inspect
        │                             (RolloutPlanService planning only)
        └──►  plan() renders; it never touches the cluster at all
```

`plan()` is a pure renderer: it holds no cluster reference, so it cannot
change traffic even by accident. `inspect()` is the only method that reads.

### 2.1 Read surface

* `READ_VERBS = {"get"}` — the verb is host-owned and host-validated; the
  operation set (`ReadOperation`) is closed and the resource for each
  operation is a module constant.
* Every variable element (namespace, route/service name, app label,
  kubeconfig context, kubectl binary) is validated as a Kubernetes name,
  label value or context name before it reaches the argv. There is no
  `run(argv)` escape hatch and no `--raw`.
* Reserved system namespaces (`kube-system`, `kube-public`,
  `kube-node-lease`, `default`, `local-path-storage`) are refused outright,
  so a misconfiguration fails closed instead of reading cluster plumbing.
* Output is bounded (256 KiB), parsed strictly, and every failure text is
  bounded and redacted (credential-shaped tokens and filesystem paths
  removed) before it can reach `ObservedTrafficState.detail`.
* Configuration is a frozen snapshot taken once at construction
  (`TrafficReadConfig.from_environment`), so a single observation cannot be
  assembled from configuration that changed half-way through.

## 3. What this phase does NOT add

* **No mutation provider.** No `TrafficMutationProvider`, no apply/rollback
  wiring, no `kubectl patch`/`subprocess` mutation from the application, no
  automatic HTTPRoute patching from rollout state, no weight computation in
  the production control plane, no traffic-mutation endpoint or service.
* **The Phase 8.7-A boundary is untouched** and still fails closed:
  `TrafficMutationPort.apply/rollback`, `UnavailableTrafficMutationProvider`,
  `TrafficMutationRequest` and `TrafficMutationResult` are unchanged, and
  the observation package does not import them (test-enforced).
* **The production topology is untouched.** `k8s/deployment.yaml` is
  unaffected; the reserved `k8s/progressive` overlay is never referenced
  from it. The observation client is an incident-service component whose
  *target* is host-owned configuration; B.1 does not wire it into any
  runtime entry point, endpoint or stage.

**This phase does not mutate traffic and does not make traffic mutation
possible.** The only component that ever patches a route is the E2E driver,
in a disposable cluster, to create proof states.

## 4. The three truth classes stay separate

Every record keeps three things apart, exactly as B.0 does:

* `configured` — the observed route's backendRefs and weights, read back
  from the API server (never from a manifest on disk);
* `controller` — what the controller reports about that route (Accepted,
  ResolvedRefs, observedGeneration vs the route's generation);
* `observed` — the target identity the adapter resolved and its
  `percentage`.

`observed.percentage` is the **effective configured share derived from the
observed live weights** (`canary / (stable + canary) * 100`) — it is *not* a
sampled request percentage. Request-level measurement is B.0's job; the
evidence artifact keeps the two apart and says so in a `configured.note`
field on every record.

Gateway API `weight` is proportional. The adapter therefore reports the
share, never the raw weight: weights `25/75` are a 75% canary share, and
`1/9` is 90%. A share that is not an exact integer percentage (for example
`2/3`) is **not rounded** — the observation fails closed instead.

## 5. Failure semantics (fail closed)

`UNKNOWN` — the cluster cannot support an answer:

* the route, a backend Service, or the Service's ready endpoints are
  missing or unreadable;
* the API server is unavailable or a read fails;
* a weight is malformed (a string, a bool, a float, `null`), negative, or
  both weights are zero (no share exists);
* the share is not an exact integer percentage;
* an endpoint carries no Pod `targetRef`, or a ready endpoint is not
  visible in the pod listing (its workload identity cannot be proved);
* the Gateway controller has not reported `Accepted=True` for the route
  (missing acceptance status or explicit `Accepted=False`).

`CONFLICT` — the cluster contradicts itself or the request:

* duplicate `backendRef` names, more than two backends, more than one
  weighted rule;
* two backends claiming the same track, a backend with no track identity,
  or a backend that is not part of the observed topology;
* an endpoint the Service's selector does not select, or one carrying the
  wrong track;
* both tracks resolving to the same workload identity, or two Deployments
  matching one track's pods;
* the controller reporting `ResolvedRefs=False` while every referenced
  backend exists;
* a request whose claimed `source_sha`/`deployment_run_id` contradicts the
  observer's host-owned configured binding.

A conflict is **never downgraded** to `UNKNOWN`: contradictory cluster truth
is a finding, not an absence of information. When both exist, `CONFLICT`
wins.

## 6. Target identity

Identity is the deterministic `<namespace>/service/<name>` — stable and
canary are two independently addressable Services. Pod names, UIDs, images
and the release-identity carrier are recorded as *evidence*; they never
define the identity, and an ambiguity in them is a conflict rather than a
guess. The adapter additionally proves the two endpoint sets are disjoint,
because two Services pointing at the same workload would make a canary
comparison meaningless.

## 7. The binding rule (§14)

The observer carries a **host-owned** expected binding
(`expected_deployment_run_id`, `expected_source_sha`) taken from trusted
configuration — never from the request. `inspect(run, sha)` reports a
binding only when the request matches it:

* match → `configured-attestation` (the observation is attributed to the
  request *because the host says so*);
* mismatch → `CONFLICT` with basis `request-vs-configured-mismatch` (a
  shadow `UNKNOWN` would hide a caller that is looking at the wrong
  release);
* no configured binding → `UNKNOWN` with basis `unbound`. A
  request-carried identity is **never** trusted and never echoed back.

The B.0 workloads carry no `DEVOPS_DEPLOYMENT_ID`/`DEVOPS_SOURCE_SHA` env
vars (`k8s/progressive/workloads.yaml` sets `ARES_TRACK` only), so there is
no cluster-side identity to invent a binding from. When a workload *does*
carry the repository's release-identity carrier, the adapter records it as
evidence; it does not use it to establish the binding, because a progressive
topology legitimately runs two revisions at once.

## 8. Live proof

`e2e/traffic_observation_kind_e2e.py` reuses Phase 8.7-B.0's proven
machinery verbatim (preflight, pinned-stack checks, fixture render/apply,
readiness gates, weight patching, sampling) and observes the resulting live
states through the **real application provider**, with a fresh read client
for every observation. Each observation is cross-checked against an
independent `kubectl` read taken by the driver.

| check | what it establishes |
| --- | --- |
| `observation:committed-95-5:*` | the committed state is observed as 5% canary, identities and configured weights match an independent read |
| `observation:all-stable-100-0:*` | 0% canary is a *known* observation of 0 — not "unknown" |
| `observation:all-canary-0-100:*` | the reverse direction, 100% |
| `observation:negative-missing-backend:*` | a backendRef naming a Service that does not exist → `UNKNOWN`, no identity, no percentage |
| `observation:negative-zero-weights:*` | an all-zero weight pair → `UNKNOWN`, no share invented |
| `observation:restored-95-5:*` | the committed state restored is observed again — no caching, a real re-read |
| `observation:binding-mismatch:*` | a contradicting request → `CONFLICT`, nothing echoed |
| `observation:unbound:*` | no configured binding → `UNKNOWN`, the request's identity is not echoed |
| `observation:read-only:no-cluster-write` | a batch of accepted, contradicted and refused observations leaves the route's `resourceVersion` and `generation` untouched |
| `observation:live-traffic-agrees` | 500 real requests through the Envoy data plane are consistent with the adapter's configured reading at 4 sigma (a triangulation; B.0 owns the traffic proof) |
| `observation:states-distinguishable` | the observed shares separate the live states (5 / 0 / 100 / 5) |

The driver mutates proof states only with `kubectl patch` (B.0's helper),
and its own evidence records `application_capability: false`.

## 9. Read-only guarantees

* **Static:** the closed operation set, the single read verb, the
  deny-list of mutating subcommands, the reserved-namespace refusal and the
  absence of any write call site are asserted by tests over both modules.
* **Structural:** the provider exposes `inspect`/`plan` only; a test asserts
  it has no `apply`, `rollback`, `patch`, `replace`, `delete`, `create`,
  `scale` or `mutate` member, and that `plan()` contains no client
  reference.
* **Live:** the E2E job observes the same route many times and shows its
  `resourceVersion`/`generation` unchanged.
* **Boundary:** the observation package never imports
  `traffic_mutation_boundary`, and `TrafficControllerPort` is still not a
  mutation interface.

## 10. Tests

* `tests/test_phase_8_7_b_1_traffic_observation_adapter.py` — the adapter:
  read policy, client bounds/parsing/redaction, live-shaped topology
  observations, every `UNKNOWN` and `CONFLICT` path, the binding rule, the
  read-only guards, the evidence shape, and three non-vacuous controls.
* `tests/test_phase_8_7_b_1_driver_control_flow.py` — runs the **real** E2E
  driver against a stub cluster (only the process layer is faked) and
  proves it goes green on a healthy topology and red when the adapter
  caches an answer or a read fails.
* `tests/test_phase_8_7_b_0_weighted_traffic_topology.py` — unchanged: the
  8.7-A boundary is still untouched and the application still contains no
  Gateway API/gateway-controller tokens outside these two new modules.

Local totals for this phase: `pytest tests/ deployment_service/tests` →
1342 passed, 1 skipped, 206+ subtests. Three source-mutation controls were
run against the real implementation and reverted — removing shared-identity
detection failed 1 test, silently coercing weights failed 3, and upgrading
refusals to `KNOWN` failed 4 — so the fail-closed rules are enforced by
tests that bite, not by tests that pass for their own reasons.

## 11. Limitations

The limitations of this phase are stated, not hidden.

* The adapter observes **configuration and target identity**, not request
  behaviour. It cannot say what fraction of traffic was served by the
  canary; only sampling can (B.0).
* It models a **two-track** (stable/canary) weighted route. A route with
  more than one weighted rule, more than two backends, or a share that is
  not an exact integer percentage is refused rather than approximated.
* Observation is point-in-time: a controller reconciliation may land
  between two reads. The driver mitigates this by waiting for the API
  server's generation to change before observing, but a production caller
  must treat consecutive observations as separate facts.
* B.1 is **not wired into any runtime path**. No endpoint, stage or
  service consults the observer yet; doing so is a separate, explicitly
  authorized step.
* Nothing here promotes, pauses, aborts or rolls back a release, and the
  application still cannot change traffic.

## 12. Defects caught before CI

The driver is un-runnable locally (no container runtime in the development
sandbox), so the stub-cluster control-flow test was written first — and it
found four real defects in the drift-then-test gap before any CI run:

1. the target namespace was derived from "the fixture declares one
   namespace", but the fixture legitimately spans two (the Envoy data plane
   lives in `envoy-gateway-system`); it is now taken from the route and
   every workload must agree;
2. the availability cross-check used the committed-name weight map, which
   raises in exactly the state it was meant to verify — the missing-backend
   state;
3. the same check used the proportional-share helper, which raises on an
   all-zero weight pair (also a state under test);
4. the restore step matched the canary backendRef by its *committed* name
   while the driver had deliberately replaced it, so the restore silently
   matched nothing.

Each is now covered by the control that found it.

## 12.1 A defect that reached CI

The incident service audits **every production file that spawns a
process**: `incident_service/application/commands/test_execution_authority.py`
holds a recorded allowlist per side-effect pattern, and its drift test
fails on anything unrecorded. The new read client was not in it, so the
incident-service job failed on the phase commit while the platform suite
was green — `pytest tests/ deployment_service/tests` does not collect
`incident_service`'s in-package test modules, which is where that audit
lives.

The fix records the file in the table with the same kind of justification
the Phase 8.6-A adapters carry (host-built argv, host-owned verb, no shell,
no `run(argv)`, no mutating subcommand reachable), and this phase's own
tests now assert the registration and that nothing else in the observation
package spawns a process. The lesson is the one this repository keeps
re-learning: a green local suite over the directories you remembered is
not a green build.

## 13.1 Controller-acceptance hardening corrective

The observation adapter now fails closed unless the Gateway controller explicitly
reports `Accepted=True` for the observed route. A missing `Accepted`
condition or `Accepted=False` is `UNKNOWN`, never `KNOWN`. This prevents
a structurally healthy-looking route from being treated as mutation authority
when the controller itself has not accepted it. The corrective adds explicit
adversarial tests for both cases; it does not change the trusted mutation
boundary or introduce any write capability.

## 13. Next step

Phase 8.7-B.2 is the trusted mutation provider (apply/rollback through an
explicitly authorized path, with the observation adapter as its read side).
It is **not** implemented, and nothing in B.1 should be read as implementing
it.
