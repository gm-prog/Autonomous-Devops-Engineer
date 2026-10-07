# Phase 8.7-B.0 — Weighted Stable/Canary Traffic Topology

Phase 8.7-A defined *what a traffic mutation would be* and shipped a
boundary that refuses to perform one. It also recorded a verified
limitation: the repository had **no weighted topology at all** — a single
plain `Service` in front of a single Deployment — so a provider would
have had nothing real to address.

This phase removes that limitation. The repository now contains a real,
executable, observable weighted routing topology built from the
Kubernetes **Gateway API**, implemented by **Envoy Gateway**, plus a Kind
E2E that proves with live HTTP traffic that the weights govern routing.
It is a topology/infrastructure foundation: **the application still
cannot change traffic**, and nothing in this phase gives it the ability
to.

## 1. Current architecture

The chain an operator can now trace, and the boundary that stops it:

```
gate evaluation (8.7-A)                 human/CI approval, deterministic
        │
        ▼
rollout state (stage 5 → 25 → 50 → 100) authoritative, durable
        │
        ▼
RolloutPlanService → TrafficControllerPort      READ-ONLY: inspect + plan
        │                                       (no mutation method exists)
        ▼
TrafficIntent (desired stable/canary percentages)
        │
        ▼
TrafficMutationPort  ←── UnavailableTrafficMutationProvider   FAILS CLOSED
        │                     (apply/rollback raise; nothing is applied)
        ▼
        ✗  no application path crosses this line today
        :  the weighted topology below is real, but the application
           has no provider, no client and no credentials for it
        │
        ▼
Kubernetes Gateway API topology on the cluster
GatewayClass → Gateway → HTTPRoute(weighted backendRefs)
                              ├─ Service ares-stable → Deployment ares-stable
                              └─ Service ares-canary → Deployment ares-canary
```

Two facts define the phase, and both are enforced by tests:

1. **The topology is real.** Two independently addressable workloads,
   reached through a real Gateway API data plane, split by explicit
   weights on the route. No python router, no single pod set wearing two
   labels, no comment claiming a split that does not exist.
2. **The application does not control it.** No application module
   contains `HTTPRoute`, `gateway.networking.k8s.io` or `envoyproxy.io`
   in executable code; the 8.7-A port surface is still `apply`/`rollback`
   only; the only implementing provider is the raise-only default.

## 2. The concrete resources

Committed as a **reserved overlay** in `k8s/progressive/` — never
referenced by the production manifests, so
`kubectl apply -f k8s/deployment.yaml` keeps working on a cluster with no
Gateway API CRDs installed:

| Resource | Name | Purpose |
| --- | --- | --- |
| `Namespace` | `ares-traffic` | isolates the E2E topology |
| `GatewayClass` | `ares-gatewayclass` | `controllerName: gateway.envoyproxy.io/gatewayclass-controller` — a real implementation, not a placeholder |
| `EnvoyProxy` | `ares-envoy-proxy` (`envoy-gateway-system`) | data-plane config for the class; `envoyService.type: ClusterIP` because Kind has no cloud load balancer and the sampler runs in-cluster |
| `Gateway` | `ares-gateway` | one HTTP listener on port 80, `allowedRoutes` from its own namespace |
| `HTTPRoute` | `ares-route` | exactly one rule, path prefix `/`, two `backendRefs` with explicit weights |
| `Service` | `ares-stable`, `ares-canary` | ClusterIP, selector `{app: ares-traffic, track: <track>}` |
| `Deployment` | `ares-stable`, `ares-canary` | one pod set each, `ARES_TRACK` baked into the image and reported on every response |

The only way a later phase can honestly say "traffic moved" is by
changing the `HTTPRoute`'s weights. That resource is the remote object
8.7-B will have to address.

## 3. Weight semantics (stated precisely)

Gateway API `weight` is a **proportional** weight, not a percentage. A
backend's share of a rule is

```
share(backend) = weight(backend) / sum(weights in that rule)
```

The committed initial state is `stable: 95`, `canary: 5`, i.e.
`95 / (95 + 5) = 95%` stable and `5%` canary. The field is never itself a
percentage, and the E2E computes every reported share with that formula
from the route it reads back out of the cluster.

A weight of `0` means the backend must not be selected. This is not an
assumption about the implementation: Envoy Gateway v1.6.7's route
translator skips zero-weight backends
(`internal/gatewayapi/route.go` — *"skip backendRefs with weight 0 as they
do not affect the traffic distribution"*), which is why the `100/0` and
`0/100` proof states can honestly demand **zero** leakage rather than a
tolerance.

## 4. The E2E proof

`e2e/traffic_topology_kind_e2e.py` runs in the dedicated CI job
*Phase 8.7-B.0 weighted traffic topology E2E* against a disposable Kind
cluster. Nothing on the routing path is mocked or faked.

**Pinned prerequisites.** The stack is installed from committed digests
in `e2e/pinned-traffic-topology.txt` (downloaded and verified with
`sha256sum -c` before `kubectl` ever sees the file, exactly like the
kubectl pin; server-side apply because the CRD schemas exceed the
client-side annotation limit):

* Gateway API CRDs **v1.4.1** (`experimental-install.yaml` — the
  same bytes Envoy Gateway v1.6.7 bundles and tests against)
* Envoy Gateway **v1.6.7** (`envoy-gateway-crds.yaml`, `install.yaml`)

v1.6.7 is deliberate: it is the newest Envoy Gateway patch that still
tests Kubernetes 1.31 (this repository pins `kindest/node:v1.31.4`), and
its own module pins Gateway API v1.4.1. There is no `latest`, no branch
and no fallback anywhere in the stack; the driver re-reads the installed
CRD bundle version and the controller image tag from the cluster and
fails if they are not the pinned releases.

**Readiness before assertions.** A manifest that merely applied is never
reported as working routing. The driver waits, with explicit deadlines
and fail-closed diagnostics, for: the controller Deployment Ready; the
`GatewayClass Accepted`; the `Gateway Accepted + Programmed`; the
`HTTPRoute Accepted + ResolvedRefs` at the generation that carries the
expected weights; both Deployments available; both Services with ready
endpoints; the Envoy data plane discovered by its owning-gateway labels
and Ready. It then also verifies, from the cluster rather than from the
selectors, that the two Services resolve to **disjoint** endpoint sets.

**Traffic.** An in-cluster sampler Job sends real HTTP requests through
the real Envoy data plane and attributes each response by the
`X-Ares-Track` header the workload itself sets, cross-checked against the
JSON body. Three states are measured, the committed one first:

| State | Weights (proportional) | Samples | Requirement |
| --- | --- | --- | --- |
| committed initial | stable 95 / canary 5 | 2000 | canary share within `5% ± 1.95pp` — **never** an exact value |
| all stable | stable 100 / canary 0 | 500 | every response from stable; **zero** canary |
| all canary | stable 0 / canary 100 | 500 | every response from canary; **zero** stable |

Weights are changed for proof states by the E2E driver's `kubectl patch`,
inside a disposable cluster. That is **test infrastructure** — the
application has no equivalent, and the driver never imports the 8.7-A
boundary. After the proofs the driver restores the committed `95/5`.

**Tolerance methodology.** The data plane picks a backend per request, so
the observed count is `Binomial(n, p)`. The accepted band is the
two-sided 4σ normal-approximation interval,
`p ± 4·sqrt(p(1-p)/n)`: for `p = 0.05`, `n = 2000` that is
`[3.0506%, 6.9494%]`. The probability of failing a *healthy* route is
`~6.3e-5`, while a materially wrong split is rejected with probability
~1 — a true 10% split sits 4.5σ outside the interval and a 1% split
9.2σ outside. The band is derived from the sampling distribution, not
chosen to make a weak test pass, and an exact `5.000000%` assertion is
never made.

**Convergence.** Between the patch and the measurement the driver waits
for the controller to accept the new generation *and* for a bounded
40-request pilot to show the data plane serving the new state. Pilot
results are recorded and excluded from the measured sample.

**Negative probe.** After the proofs, a *second* HTTPRoute whose
`backendRef` names a Service that does not exist is applied: the
controller must flag it (`ResolvedRefs=False`, reason reported) and
requests matching it must **not** be answered by a healthy backend. The
route is deleted afterwards and is not part of the committed fixture.
Separately, `e2e/traffic-topology/mutation_probe.py` tampers with an
**isolated copy** of the fixture (selector overlap, swapped backendRefs,
removed canary ref, altered/zero/missing weights, duplicate backend, TLS
listener, extra port, floating image tag, track-env mismatch, extra
route, controller swap) and requires the verifier to catch every one; the
repository tree is asserted byte-identical before and after.

**State separation.** Evidence keeps three things apart and never
collapses them: **configured** (the HTTPRoute spec read back from the API
server), **controller** (generation, `Accepted`, `ResolvedRefs`,
`Programmed`), **observed** (the actual response counts). A route that
*says* 5% is never reported as evidence that 5% *was observed*.

**Evidence and cleanup.** The run seals a machine-readable artifact
(`e2e-evidence/traffic-topology-e2e.json` plus a `.sha256` sidecar) that
is uploaded, prints a summary in the job log, and records the cluster
version, image identities, endpoints, per-state statistics and
diagnostics. The cluster is always destroyed — by the driver when asked,
and by an `if: always()` workflow step regardless.

## 5. What is NOT implemented

Explicit, because the point of this phase is the boundary:

* **No `TrafficMutationProvider`.** The 8.7-A boundary is unchanged and
  its only implementer is still the raise-only default.
* **No automatic HTTPRoute mutation.** Nothing in the application reads,
  patches or applies an `HTTPRoute`; the only weight changes anywhere are
  the E2E driver's proof states in a disposable cluster.
* **No rollback execution.** `rollback` still raises; no engine, no
  scheduler, no queue.
* **No mutation API.** No endpoint, service call or CLI through which an
  operator could request a traffic change.
* **No rollout-to-topology wiring.** No rollout stage, gate or plan is
  connected to the route; the plan remains read-only.
* **No autonomous routing changes.** No promotion, pause, abort or
  auto-rollback behaviour, and no feedback from the topology into the
  control plane.
* **No production dependency.** The production manifests are untouched
  (plain `Service`, no Gateway API objects), and the overlay is never
  referenced from them.
* **No mesh, no Ingress migration, no Argo/Flagger, no cloud LB, no DNS
  automation, no TLS, no auth, no dashboards** — none of that is needed
  to have a real weighted topology, so none of it is here.

## 6. What Phase 8.7-B.1 will add

Phase 8.7-B.1 is the **trusted production-side observation adapter**: the
read-only half that lets the control plane learn what the topology
actually is before anything is allowed to change it. It must arrive with
its own read-only credentials, its own fail-closed unavailability path
and its own tests, and it must keep the same discipline this phase
established — configured state, controller state and observed state stay
distinct, and observation is never mistaken for mutation.

Only after such an adapter exists can a later phase honestly implement a
provider against `HTTPRoute` weights. Today, the honest statement is:
**the topology is real, the weights govern routing, and the application
still cannot touch them.**

## 7. Evidence of this phase

* Static contract and identity/safety tests:
  `tests/test_phase_8_7_b_0_weighted_traffic_topology.py`.
* Static contract module: `e2e/traffic_topology.py`.
* Mutation (negative) probe: `e2e/traffic-topology/mutation_probe.py`.
* Cluster proof: `e2e/traffic_topology_kind_e2e.py`, run by the
  *Phase 8.7-B.0 weighted traffic topology E2E* CI job, whose sealed
  artifact carries the per-state configured/controller/observed records,
  the tolerance methodology and the run's diagnostics.

**What the first CI run caught.** The job's first execution failed one
second into the build step, before the driver existed on the timeline:
the workload fixture declared `ARG TRACK` above `FROM` and used it inside
the stage. BuildKit resolves a variable against the *stage's* build args
(`dockerfile2llb/validations.go`, `reportUnmatchedVariables`), so that is
an `UndefinedVar` warning — and the fixture carries `# check=error=true`,
which makes it fatal. The declaration now lives in the stage that uses
it, and
`ContainerFixtureTests.test_build_arguments_are_declared_in_the_stage_that_uses_them`
asserts the rule for both fixtures so it cannot come back silently. The
step also mirrors every build/load failure into the step summary and into
`::error` annotations, because a silent one-second failure with no
retrievable log is not diagnosable.

The second run of the job reached the cluster and stopped one step
later: the driver asked for the API server version with
`kubectl get --raw=/version -o json`, which kubectl rejects outright
("--raw and --output are mutually exclusive") because `kubectl_json()`
appends `-o json` and a raw endpoint returns JSON on its own. The version
probe now goes through a dedicated `kubectl_raw()` that adds no output
flag, the check itself is unchanged (the real API server version is still
read from the live cluster and recorded), and
`ServerVersionProbeTests` pins the argv of the call site — including a
negative control that proves the rejected `--raw … -o json` shape is
recognised as invalid.

A third defect was found while replaying the driver against a stubbed
cluster (`sh`/`kubectl` replaced by an in-memory cluster that answers
reads and applies patches): the cleanup path called `shutil.rmtree`
without importing `shutil`, which would have thrown away the sealed
evidence of a complete run. It is fixed, `StaticIntegrityTests` now fails
on any name used but bound nowhere in the CI-only modules, and the same
harness confirms the driver returns 0 with 34/34 checks on a healthy
topology, 1 when a sampler report is unparseable, and 1 when a single
response leaks from a weight-0 backend.

The fourth run reached the fixture stage and stopped on a defect of its
own: the driver applied the rendered fixture with one
`kubectl apply -f <directory>`, and kubectl walks a directory in
*lexicographic* order — `namespace.yaml` sorts after `gateway.yaml` and
`httproute.yaml`, so the API server rejected those two namespaced objects
with `namespaces "ares-traffic" not found`. Replaying the pre-fix call
against the stub cluster (which now models namespace existence) fails the
same way, with the same `… created` / `NotFound` output shape the run
reported. The fixture is now applied namespace-first, one file per
`kubectl` call, so a failure also names the file that caused it.

The *reporting* was part of the defect: the driver's message was
multi-line, and GitHub ends an `::error` annotation at the first newline,
which is why the run showed only `topology fixture failed:  created` — a
fragment of kubectl's own output — and hid the API server's error
entirely. Failure text is now collapsed onto one line
(`one_line()`), failing checks are annotated line by line, and
`kubectl_apply` reports `rc`, `stderr` and `stdout` with the file that
was being applied. `FixtureApplyOrderTests` covers the ordering
(including a non-vacuous check that the fixture layout really has the
hazard), the file-attributed error, the one-line collapsing, and a static
guard that the directory apply cannot come back.
