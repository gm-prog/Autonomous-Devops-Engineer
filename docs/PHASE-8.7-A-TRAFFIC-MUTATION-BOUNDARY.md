# Phase 8.7-A — Controlled Traffic Mutation Boundary

Status: **contract only — no traffic is mutated by this phase.**
Module: `devops-ai-platform/incident_service/application/services/traffic_mutation_boundary.py`
Tests: `devops-ai-platform/incident_service/application/services/test_traffic_mutation_boundary.py`

---

## 1. Current architecture

Progressive release is already split into three read-only layers, and
Phase 8.7-A adds a fourth that is deliberately *not* wired to anything
that can change the outside world.

```
┌──────────────────────────────┐
│ ProgressiveReleaseGateService│  "is the evidence good enough?"
│  → durable gate evaluation   │  read-only analysis, durable record
│    (+ authoritative          │
│     evaluation_id)           │
└───────────────┬──────────────┘
                │ exact evaluation_id presented
┌───────────────▼──────────────┐
│ ProgressiveRolloutStageSvc   │  "what stage are we durably at?"
│  5% → 25% → 50% → 100%       │  fail-closed state machine over one
│  ACTIVE/PAUSED/ABORTED/      │  durable record per deployment
│  COMPLETED                   │  (CAS on the record, no in-memory truth)
└───────────────┬──────────────┘
                │ durable stage + exact evaluation
┌───────────────▼──────────────┐
│ RolloutPlanService           │  "HOW WOULD traffic change?"
│  plan() → preflight status   │  READ-ONLY. Port = inspect() + plan()
│  READY / NO_OP / BLOCKED /   │  Default provider = Unavailable → no
│  CONFLICT / INCONCLUSIVE     │  inspection, so INCONCLUSIVE, not a lie
└───────────────┬──────────────┘
                │ TrafficIntent (desired state, identity-bound)
┌───────────────▼──────────────┐
│ ── Phase 8.7-A boundary ──   │  "what WOULD a mutation be authorised to
│ TrafficMutationRequest       │   do, and what would prove it happened?"
│ TrafficMutationPort          │  Contract + fail-closed default only.
│  apply() / rollback()        │  NO provider is implemented.
└──────────────────────────────┘
```

Two separations are load-bearing and are preserved unchanged:

* **`plan != apply`.** `TrafficControllerPort` exposes exactly
  `inspect()` and `plan()`. Phase 8.7-A does **not** widen it: the
  mutation lives behind a separate `TrafficMutationPort`.
  `test_planning_port_was_not_turned_into_a_mutation_interface` fails if
  anyone adds `apply`/`rollback` to the planning port.
* **`READY != changed`.** A `READY` preflight from Phase 6.7.1 proves
  that a plan *would be* valid. It is not evidence that traffic moved,
  and nothing in this phase treats it as such.

## 2. The mutation boundary

### 2.1 Request identity binding

`TrafficMutationRequest` carries the complete authority for one
mutation. Nothing may be looked up, derived or guessed by a provider:

| Field | Why it is here |
| --- | --- |
| `deployment_run_id` | binds the mutation to one deployment run |
| `source_sha` | binds it to one exact revision (40 lowercase hex) |
| `gate_evaluation_id` | binds it to the exact evaluation that authorised it |
| `intent_id` | binds it to one rollout intent (no second identity scheme) |
| `stable_target` | the trusted stable destination |
| `canary_target` | the trusted canary destination |
| `expected_current_percentage` | the state the intent was built on |
| `requested_percentage` | the forward target |
| `observed_percentage` | what was **actually observed** immediately before |
| `observed_at` | when that observation was taken |

`from_traffic_intent(intent, observed_percentage=…, observed_at=…)`
preserves the existing intent's identity (ids, run, SHA, targets, and
the requested percentage) and binds it to the observation. The intent's
`None` targets — which `RolloutPlanService` leaves unset until trusted
observation proves them — are refused rather than invented.

### 2.2 Validation (fail closed, at construction)

| Rule | Reason |
| --- | --- |
| identifiers non-empty strings, ≤ 128 chars | no blank/oversized identity |
| `source_sha` exactly 40 lowercase hex | mixed case is not the same commit |
| percentages are honest `int` in `[0, 100]` | `bool` is an `int` subclass; `True` is refused |
| `observed == expected_current` | a valid *target* is not an *observation* |
| `requested != expected_current` | a no-op is not a mutation |
| `requested > expected_current` | backward moves are rollback, not apply |

All of these raise `InvalidTrafficMutationRequest` **before** a provider
is handed anything, so an untrustworthy request cannot reach one.

### 2.3 Deterministic digest

`request.digest()` is a SHA-256 over a JSON canonicalisation of the full
payload with a fixed field order, explicit `sort_keys`, no implicit
clock, and no dependence on object identity. Equivalent requests digest
identically (including the same instant expressed with a UTC offset) and
changing any of the ten fields changes the digest. This is the value
that will later carry idempotency and audit correlation.

### 2.4 Provider interface

```python
class TrafficMutationPort(Protocol):
    def apply(self, request: TrafficMutationRequest) -> TrafficMutationResult: ...
    def rollback(self, request: TrafficMutationRequest) -> TrafficMutationResult: ...
```

Exactly two members. Deliberately absent: `inspect`, `plan` (those stay
on the planning port), `execute`, `mutate`, `apply_percentage`, and any
provider-specific member. `FORBIDDEN_PORT_MEMBERS` names the class of
widening that is not allowed.

`rollback(request)` undoes the approved forward transition described by
`request`. It is not handed a separately-shaped "backward" request,
because a request can only describe a forward move
(`requested > observed`); reversing one is a distinct operation with its
own authorisation — which is why it is a distinct member and never a
negative `apply`.

### 2.5 Verification semantics

`TrafficMutationResult.verified` is mandatory and explicit — there is no
default. Three facts that are often conflated are kept apart:

1. the provider call returned,
2. the provider accepted the request,
3. the remote state is now verified at the requested percentage.

Only (3) is `verified=True`. A result with `verified=False` (and
therefore no claimed `remote_percentage`) is a first-class outcome and
is never rewritten into success anywhere in this phase. Two integrity
rules keep the claim meaningful: `request_digest` must be one of *our*
sha256 digests (64 lowercase hex) so a result can only correlate with a
real request, and `verified=True` requires an explicit
`remote_percentage` — a verification with no observed value proves
nothing.

### 2.6 Fail-closed default

`UnavailableTrafficMutationProvider` is the default: both `apply()` and
`rollback()` raise `TrafficMutationProviderUnavailable` (a
`TrafficMutationError`) and return nothing. It does not simulate a
traffic change, does not write local state and call it traffic, and
holds no mutable attributes. The only objects in this module that
implement the port surface are the protocol itself (no bodies) and this
provider — enforced structurally, not by comment.

## 3. Current topology limitation (verified fact)

The repository does **not** establish a weighted stable/canary traffic
routing mechanism:

* `k8s/deployment.yaml` contains exactly a `Namespace`, a `ConfigMap`,
  one `Deployment` (`devops-gateway-deployment`, plain rolling update),
  one plain `Service` (`devops-gateway-loadbalancer`, selector
  `app: devops-gateway`) and one `HorizontalPodAutoscaler`. There is no
  weight/percentage field anywhere in it.
* No `Ingress`, `HTTPRoute`, `Gateway`, `VirtualService` or service-mesh
  resource exists anywhere in the repository.
* The deployment-service kubectl runner exposes no traffic operation.

Consequently Phase 8.7-A ships a boundary and a fail-closed default
**and no provider**. Inventing a weighted split that the cluster does
not implement would be architecturally false — and would be exactly the
kind of "looks like a traffic change" claim this boundary exists to
prevent.

## 4. Explicit non-goals

Phase 8.7-A does **not**: perform real traffic mutation; ship a
production traffic provider; add kubectl/subprocess/HTTP/Kubernetes/
cloud/service-mesh calls; add an API endpoint; change gate policy, the
rollout stage sequence or the state machine; redesign persistence; add
Kubernetes manifests or a mesh. The module imports no execution
mechanism at all, which is asserted by an AST test over its imports,
call names and attribute chains.

## 5. Phase 8.7-B prerequisites

A real provider may only be added in Phase 8.7-B, and only when all of
the following hold:

1. **A real weighted stable/canary topology exists and is verified** —
   checked-in manifests and live observation, not an assertion.
2. **Stable and canary identities come from trusted observation**, never
   from local configuration guessing.
3. **The provider can verify the exact current remote percentage**
   immediately before mutating it.
4. **Forward mutation is bounded to the authorised rollout target** —
   never an arbitrary percentage, never a skip, never a reversal.
5. **Post-mutation remote state is verified**, and `verified=True` is
   only set from that verification.
6. **Failures, duplicates, unknown timeouts and concurrent requests fail
   closed** — no retry that could double-apply, no optimistic success.
7. **Rollback semantics are explicit and separately controlled**, and
   are not reachable through `apply()`.
8. **Real CI/staging E2E evidence demonstrates the actual remote traffic
   change and its verification**, with the request digest and the
   observed before/after percentages recorded.

> A `READY` result from existing Phase 6.7.1 planning is not evidence
> that traffic has actually changed.

## 6. Known limitation of this phase

`from_traffic_intent()` imports `rollout_plan_service` for the
`TrafficIntent` type, so importing the boundary transitively imports the
incident-service application layers. That is intentional — it is what
makes the intent identity provably the repository's existing one rather
than a parallel scheme — but it means the boundary is not importable in
isolation from a stripped environment. The boundary itself still adds no
execution capability: the import graph is asserted by test to contain no
infrastructure, Kubernetes or deployment-service module.
