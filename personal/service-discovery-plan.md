# Service Mesh: Bulletproof Service Discovery & Load Balancing for 100s of RPC Endpoints

## Context

yoq already has the pieces of a service data plane, but they are not yet a reliable system at cluster scale:

- DNS service discovery is currently last-write-wins name → IP, backed by `service_names`, with a fixed in-memory registry and a 256-entry eBPF DNS map.
- L4 load balancing already exists, but it is consistent-hash plus conntrack, not a full service registry. It currently supports 16 backends per VIP.
- Health checking is a separate fixed-size runtime (`64` slots) and directly registers/unregisters endpoints in DNS on probe transitions.
- Container startup/teardown, DNS registration, health checking, and network policy all touch related state independently.

That works on the happy path, but it is fragile under restart, partial failure, stale events, node loss, BPF reload, and migration. The goal of this feature is not just "multi-endpoint services". The goal is a service-discovery subsystem that can be rebuilt deterministically from persisted state, survive partial failure, and make failure behavior explicit.

The approach remains **no sidecars**. yoq itself owns the data plane:

- userspace + eBPF for DNS and L4 steering
- an in-process proxy for optional L7 HTTP routing
- SQLite + raft for durable cluster state

## Goals

- One service name maps to many endpoints across nodes.
- Every service has a stable VIP that does not depend on any endpoint IP.
- DNS always resolves to the service VIP, not a backend IP.
- Only healthy and administratively active endpoints are eligible for traffic.
- Endpoint removal on explicit stop/node loss is fast and does not wait for probe timeout.
- Process restart, BPF reload, or leader failover can rebuild derived state without app changes.
- Migration from the current `service_names` path is staged, observable, and reversible.
- Failure behavior is explicit: no silent truncation, no stale backends lingering forever, no hidden split-brain between DB and BPF.

## Non-Goals For Initial Delivery

- General-purpose mesh features for all protocols.
- Automatic mTLS between services.
- Weighted or least-connections LB in the first cut.
- HTTP/2, gRPC-specific proxy semantics, or external xDS-style control planes.

The first version should solve durability, correctness, and operability first. Fancy policy comes after the foundation is stable.

## Correctness Invariants

- VIPs are allocated once per service and never derived from endpoint IPs.
- Durable service membership and VIP allocation are the source of truth. DNS maps, LB maps, health state, and compatibility mirrors are derived state.
- Runtime health is **not** persisted as authoritative cluster state. Probe results are ephemeral observations.
- Only one subsystem programs DNS/LB/policy derived state: a service reconciler. Startup, teardown, health checks, and node-failure detection submit intents/events; they do not mutate BPF/DNS state directly.
- Endpoint identity is monotonic. Stale events from an older container incarnation must not overwrite newer state.
- There is no silent overflow. If a service exceeds a configured endpoint limit, the system surfaces an error/metric/API status and rejects or quarantines the excess endpoints intentionally.
- A service with zero eligible endpoints has explicit behavior:
  - DNS still resolves to the VIP.
  - L4 drops or fails new connections quickly rather than black-holing them indefinitely.
  - L7 returns `503 Service Unavailable`.
- Explicit stop, force-remove, and node-loss events remove endpoints from eligibility immediately. Health probes are not the only removal path.
- Boot recovery must be able to reconstruct the full data plane from SQLite plus live node/container state, then converge without manual repair.

## Failure Scenarios To Design For Explicitly

- Container restart with same service name and a different IP.
- Duplicate register/unregister events.
- Out-of-order health results arriving after endpoint replacement.
- Node partition or agent heartbeat loss.
- Process crash after DB commit but before BPF map update.
- BPF map update failure or map-full condition.
- DNS interceptor unavailable while userspace DNS is still running.
- Boot with stale endpoint rows for containers that no longer exist.
- Leader failover during VIP allocation or service registration.
- Migration interrupted halfway through dual-write/dual-read.
- Restore from an older backup that predates the new tables.
- Admin force-removal or drain of a single endpoint while the service remains healthy overall.

---

## Phase 0: Guardrails, Ownership, and Rollout Controls

**Goal:** Prevent the implementation from creating yet another set of partially overlapping registries.

### 0a. Feature flags and cutover switches

- Add explicit rollout flags:
  - `service_registry_v2`
  - `service_registry_reconciler`
  - `dns_returns_vip`
  - `l7_proxy_http`
- Make each flag independently observable via logs/API/metrics.
- Support running old and new paths in shadow mode before cutover.

### 0b. Single-writer rule

- Define the reconciler as the only writer for:
  - DNS name → VIP programming
  - VIP → eligible backend programming
  - compatibility mirrors such as `service_names`
- Existing direct writes from:
  - container networking startup
  - container teardown
  - health checker transitions
  must be converted to enqueue events/intents instead of mutating DNS/BPF directly.

### 0c. Reliability targets

- Define concrete targets up front:
  - explicit stop/remove: endpoint removed from eligibility in `< 1s` locally
  - node heartbeat loss: endpoints removed on node-failure path, not probe timeout
  - unhealthy endpoint via probes: removed within a bounded window based on `interval` and `retries`
  - boot rebuild: reconciler can repopulate DNS/LB state from DB without operator action
- Define compile-time limits explicitly and surface them through the API.

### 0d. Test harness requirements

- Add integration tests that exercise restart, stale DB rows, node-loss, and BPF resync.
- Add fault-injection hooks for:
  - BPF map update failure
  - DNS interceptor unavailable
  - raft apply failure / stale replica
  - map-full / endpoint-overflow

**Files:** new `src/network/service_reconciler.zig`; modify `src/network/setup/container_runtime.zig`, `src/manifest/health/checker_runtime.zig`, startup/orchestrator paths that currently write DNS directly

---

## Phase 1: Canonical Service Registry and Persistence

**Goal:** Create a durable service model that separates service identity, endpoint membership, and runtime observations.

### 1a. Durable schema

- Add a durable `services` table:
  ```
  services(
    service_name TEXT PRIMARY KEY,
    vip_address TEXT NOT NULL UNIQUE,
    lb_policy TEXT NOT NULL DEFAULT 'consistent_hash',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  )
  ```
- Add a durable `service_endpoints` table:
  ```
  service_endpoints(
    service_name TEXT NOT NULL,
    endpoint_id TEXT NOT NULL,
    container_id TEXT NOT NULL,
    node_id INTEGER,
    ip_address TEXT NOT NULL,
    port INTEGER NOT NULL,
    weight INTEGER NOT NULL DEFAULT 1,
    admin_state TEXT NOT NULL DEFAULT 'active', -- active | draining | removed
    generation INTEGER NOT NULL,
    registered_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    PRIMARY KEY (service_name, endpoint_id)
  )
  ```
- `endpoint_id` should be an explicit stable identifier, not an implicit `(service_name, container_id)` assumption. Initial implementation can derive it from `container_id + ":" + port`.
- Do **not** store probe health as authoritative persistent membership data.

### 1b. Indexes and query shape

- Add indexes for:
  - `service_endpoints(service_name, admin_state)`
  - `service_endpoints(container_id)`
  - `service_endpoints(node_id)`
  - `services(vip_address)`
- Keep query patterns cheap for:
  - list service summary
  - fetch service detail
  - remove endpoints by container/node
  - rebuild services on boot

### 1c. VIP allocation

- Create `src/network/vip_allocator.zig`.
- Allocate from `10.43.0.0/16`, separate from container subnets in `10.42.x.x`.
- VIP allocation rules:
  - once allocated, never changed implicitly
  - collision-safe via unique constraint
  - exhaustion returns a hard error with metric/log/API visibility
  - leader failover cannot allocate a second VIP for the same service
- Store VIP in `services`, not as a transient function of current endpoints.

### 1d. Store layer and cluster plumbing

- Extend `src/state/store/services.zig` with:
  - create/load/list services
  - register/update/remove endpoint rows
  - mark endpoint draining/removed
  - list endpoints by service or node
- Update cluster replication plumbing so service registry SQL is valid replicated state:
  - `src/cluster/state_machine/sql_guard.zig`
  - any SQL generators/helpers used for replicated writes
- Update:
  - `src/state/schema/tables.zig`
  - `src/state/schema/indexes.zig`
  - `src/state/schema/migrations.zig`
  - `src/state/backup.zig`
- Backups must validate and include the new tables before this feature is considered production-ready.

### 1e. In-memory service registry state machine

- Create `src/network/service_registry.zig` as a pure state machine with a small runtime wrapper.
- Inputs:
  - service created
  - endpoint registered
  - endpoint removed
  - endpoint drained/undrained
  - probe result
  - node lost / node recovered
  - boot snapshot loaded
  - BPF sync success/failure
- Derived state per endpoint:
  - durable membership fields from SQLite
  - runtime eligibility
  - runtime observed health
  - last transition timestamps
- Outputs are actions for the reconciler, not direct side effects.

### 1f. Service registry API

- Add `src/api/routes/services.zig` and wire it into `src/api/routes.zig`.
- New routes:
  - `GET /v1/services`
  - `GET /v1/services/{name}`
  - `GET /v1/services/{name}/endpoints`
  - `POST /v1/services/{name}/reconcile`
  - `POST /v1/services/{name}/endpoints/{endpoint_id}/drain`
  - `DELETE /v1/services/{name}/endpoints/{endpoint_id}`
- Service detail should expose:
  - VIP
  - total endpoints
  - eligible endpoints
  - healthy endpoints
  - draining endpoints
  - last reconcile status/error
  - overflow/degraded flags

**Files:** new `src/network/service_registry.zig`, `src/network/service_registry_runtime.zig`, `src/network/vip_allocator.zig`, `src/api/routes/services.zig`; modify `src/state/store/services.zig`, `src/state/schema/tables.zig`, `src/state/schema/indexes.zig`, `src/state/schema/migrations.zig`, `src/cluster/state_machine/sql_guard.zig`, `src/state/backup.zig`, `src/api/routes.zig`

---

## Phase 2: Deterministic Reconciler and Boot Recovery

**Goal:** Make DNS, LB, and compatibility state fully derived and rebuildable.

### 2a. Reconciler runtime

- Create `src/network/service_reconciler.zig`.
- The reconciler owns:
  - DNS name → VIP state
  - VIP → eligible backends state
  - compatibility mirror state for old consumers
  - service-level degradation status
- Reconciler inputs come from:
  - container start/stop
  - health transitions
  - manifest refresh
  - node membership changes
  - BPF/DNS component load/unload
  - boot-time DB snapshot

### 2b. Full-service reconciliation, not only incremental patching

- Do not rely only on `add_backend` / `remove_backend` deltas.
- Reconcile each service to a desired snapshot:
  - desired VIP
  - desired DNS entry
  - desired eligible endpoint set
  - desired compatibility mirror rows
- Support both:
  - full rebuild on boot / BPF reload
  - per-service resync on individual service changes

### 2c. Boot-time rebuild

- On startup:
  - load `services` and `service_endpoints`
  - prune or quarantine obviously invalid rows
  - mark runtime health as unknown
  - reconstruct DNS/LB state from durable membership plus current eligibility rules
  - trigger health checks for readiness before endpoints become eligible unless policy says otherwise
- If the DB says an endpoint exists but the container/node does not, do not immediately trust the row forever. Mark it stale and reconcile it out.

### 2d. Periodic audits and resync

- Add periodic audit loops:
  - DB vs in-memory registry
  - registry vs BPF maps
  - registry vs `service_names` compatibility mirror
- Mismatch should:
  - emit metrics/logs
  - mark service degraded
  - schedule retry with backoff
  - not require manual restart

### 2e. Compatibility mirror during migration

- Keep `service_names` during migration, but make its purpose explicit:
  - compatibility for existing network policy code and any legacy consumers
  - mirror active endpoint membership, not DNS VIP resolution
- Stop using `service_names` as the canonical DNS answer path.

**Files:** new `src/network/service_reconciler.zig`; modify `src/network/dns/registry_support.zig`, `src/network/dns.zig`, `src/network/setup/container_runtime.zig`, `src/manifest/health/checker_runtime.zig`, `src/network/policy.zig`, `src/state/store/services.zig`

---

## Phase 3: Stable VIP DNS and L4 Load Balancing

**Goal:** DNS always returns a stable VIP and L4 steering always uses the reconciled eligible endpoint set.

### 3a. DNS path returns VIP only

- Update userspace DNS and the eBPF DNS interceptor so service name lookups resolve to the service VIP.
- `src/network/dns/registry_support.zig` becomes a DNS view over reconciled service state, not the authority for membership.
- Increase DNS map capacity in line with the service limit and make overflow explicit.

### 3b. LB data plane aligned with current implementation

- Keep the first implementation aligned with existing behavior:
  - consistent-hash selection
  - conntrack for flow affinity
- Do not claim round-robin as the primary algorithm when the current data plane is not round-robin.
- Add the extension point for future `lb_policy`, but defer weighted/least-connections until after the registry is stable.

### 3c. Backend capacity and verifier-safe BPF changes

- Increase backend capacity from `16` to `64` for the first cut.
- Update:
  - `src/network/ebpf/lb_runtime.zig`
  - `bpf/lb.c`
  - generated `src/network/bpf/lb.zig`
- This is not just a map-size change. The BPF C program currently hardcodes `16`-specific bounds and verifier-safe masking. All such constants must be updated together.

### 3d. Zero-backend semantics

- Represent "service exists, no eligible backends" explicitly.
- New connections to a VIP with zero eligible backends should fail fast:
  - drop with metric/event at L4
  - return `503` at L7
- Do not quietly remove all knowledge of the VIP and black-hole traffic via unresolved routing.

### 3e. Map-full and sync failure behavior

- If LB or DNS map programming fails:
  - keep the service marked degraded
  - retry with backoff
  - expose a metric/API status
  - do not silently pretend reconciliation succeeded
- If a service exceeds `max_backends`, reject or quarantine excess endpoints explicitly and surface the problem.

**Files:** modify `src/network/ebpf/lb_runtime.zig`, `bpf/lb.c`, generated `src/network/bpf/lb.zig`, `src/network/ebpf/dns_runtime.zig`, generated `src/network/bpf/dns_intercept.zig`, `src/network/dns/registry_support.zig`

---

## Phase 4: Health Model and Endpoint Eligibility

**Goal:** Scale health checks without turning probe results into stale cluster truth or minute-long failure windows.

### 4a. Runtime health is separate from durable membership

- Replace the fixed `[64]?ServiceHealth` registry with a dynamic structure keyed by `endpoint_id` and `generation`.
- Health state is runtime-only and rebuilt on boot.
- Persist only what is needed for diagnostics if necessary, not as the source of traffic truth.

### 4b. Bounded concurrent checker

- Replace the current sequential checker with:
  - a scheduler thread that enqueues due endpoints
  - a bounded worker pool for HTTP/TCP/exec checks
  - per-check deadlines and jitter
- The target is bounded detection latency, not "eventually after a long sweep".
- A 500-second worst-case sweep is unacceptable for this feature.

### 4c. Eligibility rules

- New endpoints start as `pending` / not yet eligible.
- Eligibility requires:
  - durable membership exists
  - endpoint is not draining/removed
  - node is considered alive
  - readiness policy is satisfied
- A service can still exist with zero eligible endpoints.

### 4d. Fast-fail sources other than probes

- Endpoint removal must happen immediately on:
  - local container stop
  - force-remove
  - known node loss / agent timeout
  - manifest-driven drain/remove
- Probes are only one input into eligibility, not the only removal mechanism.

### 4e. Stale-result rejection

- Probe results must carry endpoint generation.
- If a container restarts and reuses a service name, old probe completions must be ignored.
- Unregistering an endpoint should cancel or invalidate in-flight checks.

### 4f. Backoff and flapping control

- Add jitter to intervals.
- Track last transition time and flap counts.
- Optionally impose a short recovery debounce to prevent pathological flip-flop under intermittent failures.

**Files:** modify `src/manifest/health/registry_support.zig`, `src/manifest/health/types.zig`, `src/manifest/health/checker_runtime.zig`, `src/manifest/health.zig`; integrate with `src/network/service_registry.zig` / `src/network/service_reconciler.zig`

---

## Phase 5: Migration, Cutover, and Downgrade

**Goal:** Move from the current `service_names`/direct-DNS model without breaking running clusters or blocking rollback.

### 5a. Schema-first rollout

- Ship the new tables, indexes, backup validation, and store APIs first.
- This release should not change DNS/LB behavior yet.

### 5b. Backfill

- On upgrade:
  - scan `service_names`
  - create `services` rows with allocated VIPs
  - create `service_endpoints` rows
  - mark backfilled rows so they can be audited
- Make the backfill idempotent.

### 5c. Dual-write

- Membership changes write:
  - new canonical tables
  - `service_names` compatibility mirror
- Health transitions stop directly writing DNS or `service_names`.

### 5d. Dual-read and shadow compare

- In shadow mode:
  - old path continues serving DNS/LB
  - new reconciler computes desired state and compares it
- Emit mismatch metrics/logs before cutover:
  - VIP mismatch
  - endpoint-count mismatch
  - stale endpoint mismatch
  - eligibility mismatch

### 5e. Cutover

- Enable `dns_returns_vip`.
- Enable reconciler-driven LB programming.
- Keep `service_names` mirror for compatibility until network policy and any legacy readers are migrated.

### 5f. Downgrade path

- Old binaries continue to work as long as `service_names` remains populated.
- Do not delete or stop mirroring `service_names` until at least one full release cycle after cutover.
- Backups/restores must accept both pre-feature and post-feature schemas.

### 5g. Cleanup

- Only after successful cutover and stable operation:
  - remove old direct-DNS writes from startup/health/teardown
  - migrate policy lookup away from `service_names` or keep the mirror as an intentional compatibility layer

**Files:** modify rollout wiring across `src/network/setup/container_runtime.zig`, `src/manifest/health/checker_runtime.zig`, `src/network/dns/registry_support.zig`, `src/network/policy.zig`, store/schema/backup modules, and cluster state-machine allowlists

---

## Phase 6: L7 Reverse Proxy (Opt-In, HTTP/1.1 First)

**Goal:** Add HTTP routing, retries, and circuit breaking without undermining the L4 foundation.

### Current status on `main`

The core path is in place:

- Manifest parsing and validation for opt-in `http_proxy` service config.
- Durable proxy policy stored with canonical `services` state.
- Route materialization from canonical service state into `src/network/proxy/runtime.zig`.
- Route inspection via:
  - `GET /v1/services/{name}/proxy-routes`
  - rollout status / metrics for the L7 control plane
- End-to-end HTTP/1.1 handling in `reverse_proxy.zig`:
  - parse HTTP/1.1 request
  - require `Host`
  - match host + path
  - resolve an eligible upstream from canonical endpoint state
  - rewrite and forward the request to an upstream TCP connection
  - stream the upstream response back
  - return explicit `400`, `404`, `502`, or `503` responses when forwarding is not possible
- Conservative retry support:
  - safe methods only
  - transport failure retries
  - upstream `5xx` retries
  - bounded retry budget from persisted policy
- Per-endpoint circuit breaking in the proxy runtime with open and half-open states.
- Loop prevention via proxy marker headers and rejection of re-entered requests.
- Loopback listener runtime for the L7 proxy on port `17080`.
- VIP steering control plane that maps `VIP:port` traffic into the listener for HTTP-enabled services.
- Steering readiness surfaced per route and in rollout status, including blocked reasons.

For the first cut, the proxy data path and the steering model are both in place. What remains after this point is follow-on work, not a blocker for the service-discovery rollout itself.

### 6a. Scope the first version tightly

- HTTP/1.1 only in the first cut.
- Opt-in per service or per route.
- Non-HTTP traffic stays on the L4 path.

### 6b. Reverse proxy modules

- New `src/network/proxy/` module with:
  - `reverse_proxy.zig` — listener and connection lifecycle
  - `router.zig` — host/path matching
  - `policy.zig` — timeout/retry/circuit-breaker logic
  - `upstream.zig` — eligible endpoint selection and connection pooling
- Reuse `src/api/http.zig` where practical, but do not force proxy semantics onto the API server if the abstractions diverge.

What this means in practice now:

- `router.zig` exists and matches host/path with longest-prefix wins.
- `upstream.zig` exists and selects eligible endpoints from canonical service state.
- `runtime.zig` exists and materializes routes plus readiness counts from canonical service and endpoint state.
- `reverse_proxy.zig` now proxies one HTTP/1.1 request per connection, applies retries conservatively, and records route/runtime failure state.
- `listener_runtime.zig` accepts loopback connections and hands them to the reverse proxy.

### 6c. Redirect/steering model

- Explicitly define how VIP-bound HTTP traffic reaches the proxy:
  - TC redirect / host proxy path
  - loop prevention
  - source IP preservation expectations
  - how non-HTTP traffic bypasses the proxy

Current behavior:

- VIP steering is implemented through the XDP port-mapper path using exact `dst_ip + port + protocol` matches.
- Only TCP mappings are programmed for HTTP-enabled services, so non-HTTP traffic stays on the L4 data path.
- If VIP steering is not ready, VIP traffic falls back to the L4 service path instead of being black-holed. Route status now reports that as `vip_traffic_mode = "l4_fallback"`.
- Listener start, stop, and accept-loop failure now trigger steering resync so stale VIP mappings do not linger after the listener changes state.
- Route and rollout status already surface whether steering is ready and why it is blocked when it is not.
- The proxy now sets `X-Forwarded-For`, `X-Forwarded-Host`, and `X-Forwarded-Proto` itself instead of trusting inbound values.
- Source IP expectations are now explicit:
  - the listener sees the original client source address on the steered TCP connection
  - the upstream sees the proxy as the TCP peer
  - HTTP backends must use the forwarded headers if they need original client identity

### 6d. Retry and circuit-breaker semantics

- Retries are opt-in and only for safe/explicitly configured conditions.
- Define:
  - connect timeout
  - request timeout
  - max retries
  - retryable status classes
  - per-endpoint circuit-breaker thresholds
  - half-open probing
- Service with no available upstreams returns `503`.

Current behavior:

- Matching routes return `503` when no eligible upstream exists.
- The forwarding path already applies safe-method retries for transport failures and upstream `5xx`.
- Circuit breaking is active in the proxy runtime and affects later upstream selection.

### 6e. Persistent config and reconciliation

- Add route/policy config to manifest types and persistent storage.
- Route config changes should feed the same reconciler model as service changes.

This is mostly done for the first cut:

- Manifest `http_proxy` config is parsed and validated.
- Proxy policy is persisted with canonical `services` state.
- Local deploy syncs manifest proxy config into canonical service state before proxy bootstrap.
- Runtime changes already refresh the proxy and steering control plane.
- The remaining gap is operational hardening, not config persistence.

### 6f. First-Cut Exit Criteria On `main`

The first-cut L7 feature is complete when all of the following are true:

1. HTTP-enabled services can steer VIP traffic into the loopback listener and proxy one HTTP/1.1 request end to end.
2. If steering is blocked or drifted, route and service status make that visible and report whether traffic is using the L7 proxy or falling back to L4.
3. Listener start, stop, restart, and periodic repair all converge steering state without leaving stale VIP mappings behind.
4. Loop prevention is stateless and still rejects re-entered requests after retries and listener restarts.
5. HTTP backends can recover original client identity from proxy-managed forwarded headers.
6. Non-HTTP traffic stays on the L4 path because the steering layer only programs TCP VIP mappings.
7. The implementation remains one-request-per-connection for now. Connection reuse and pooling are a later optimization, not part of first-cut correctness.

### 6g. Follow-On Work

Reasonable follow-ons after the first cut:

1. Connection reuse and upstream pooling.
2. More route-level metrics if per-service cardinality is acceptable.
3. HTTP/2 or gRPC-specific behavior, if that ever becomes necessary.

**Files:** new `src/network/proxy/reverse_proxy.zig`, `src/network/proxy/router.zig`, `src/network/proxy/policy.zig`, `src/network/proxy/upstream.zig`; modify `src/manifest/spec/shared_types.zig`, route storage/state-machine plumbing as needed

---

## Phase 7: Observability and Operability

**Goal:** Make the system debuggable when it fails, not just when it works.

### 7a. Service registry metrics

- Add:
  - `yoq_service_endpoints_total{service,state}`
  - `yoq_service_eligible_endpoints{service}`
  - `yoq_service_reconcile_runs_total{service,result}`
  - `yoq_service_reconcile_duration_seconds{service}`
  - `yoq_service_bpf_sync_failures_total{service,component}`
  - `yoq_service_zero_backends_total{service}`
  - `yoq_service_endpoint_overflow_total{service}`
  - `yoq_service_vip_alloc_failures_total`

### 7b. Health and checker metrics

- Add:
  - `yoq_service_health_checks_total{service,result}`
  - `yoq_service_health_check_latency_seconds{service}`
  - `yoq_service_checker_queue_depth`
  - `yoq_service_checker_workers_busy`
  - `yoq_service_endpoint_flaps_total{service,endpoint}`

### 7c. Access logs and event logs

- Structured events for:
  - endpoint registered/removed
  - node-loss endpoint eviction
  - reconcile mismatch
  - BPF sync failure
  - VIP allocation
  - zero-backend service
- L7 access logs remain structured JSON.

### 7d. Trace propagation

- Propagate `traceparent` / `tracestate` through the HTTP proxy.
- Generate a trace context when absent.
- Keep cardinality bounded in labels and logs.

### 7e. Operator controls

- API-visible reconcile status.
- Manual per-service reconcile trigger.
- Clear degraded/error states instead of requiring a restart to discover current truth.

**Files:** modify `src/api/routes/status_metrics.zig`, `src/api/routes/status_metrics/metrics_routes.zig`; add proxy metrics/logging modules as needed

---

## Phase 8: mTLS Between Services (Stretch)

**Goal:** Automatic mutual TLS between services without app changes.

- Reuse existing TLS and cert-store infrastructure where possible.
- Proxy terminates/originates mTLS while backends remain local plaintext if desired.
- Cert issuance, rotation, trust bundles, and failure semantics must all be designed explicitly.
- **Defer this phase** until the service registry, reconciler, and L7 path are stable.

WireGuard already encrypts inter-node traffic; correctness of discovery and routing is the higher-priority problem.

---

## Implementation Order and Dependencies

```text
Phase 0 guardrails
  -> Phase 1 canonical schema/store/registry
  -> Phase 2 reconciler + boot rebuild
  -> Phase 3 DNS VIP + L4 LB cutover
  -> Phase 4 scalable health eligibility
  -> Phase 5 migration/cutover/downgrade
  -> Phase 6 optional L7 HTTP proxy
  -> Phase 7 observability/operability
  -> Phase 8 mTLS
```

Practical implementation order:

1. Schema/store/backup/sql-guard groundwork.
2. In-memory registry + reconciler in shadow mode.
3. Boot rebuild and periodic audit.
4. DNS returns VIP.
5. LB cutover to reconciled eligible endpoints.
6. Health checker rewrite and fast-fail integration.
7. Migration cleanup.
8. Optional L7 proxy.

Phases 1-5 are the minimum foundation for a bulletproof service-discovery system. L7 and mTLS should not start until the reconciler and migration story are solid.

## Verification Matrix

- **Durable registry:** create/update/remove services and endpoints; restart yoq; verify services, VIPs, and membership rebuild correctly.
- **VIP stability:** deploy a service, record VIP, replace all backends, verify VIP stays constant.
- **DNS cutover:** `dig @10.42.0.1 service-name` always returns VIP, never a backend IP.
- **LB eligibility:** repeated connections to a VIP distribute across eligible backends only.
- **Explicit stop path:** stop one backend and verify it leaves eligibility immediately, without waiting for probes.
- **Node-loss path:** simulate lost agent heartbeat and verify all endpoints on that node are removed from eligibility.
- **Probe-driven failure:** make an endpoint fail health checks and verify removal occurs within the configured bound.
- **Stale-result rejection:** restart a container quickly and verify old in-flight probe results cannot evict the new endpoint incarnation.
- **Boot rebuild:** unload/reload BPF or restart yoq and verify DNS/LB state is reconstructed from persisted state.
- **Audit repair:** intentionally corrupt a BPF map entry and verify periodic reconciliation repairs it.
- **Overflow handling:** exceed per-service backend limit and verify the system surfaces a hard error/metric instead of silently truncating.
- **Map failure handling:** inject BPF map update failures and verify degraded state plus retry behavior.
- **Migration shadow mode:** compare old and new views and fail the rollout on mismatches.
- **Downgrade:** run a pre-cutover build against a post-schema DB while `service_names` mirror is intact.
- **Backup/restore:** restore both pre-feature and post-feature backups and verify schema validation plus rebuild behavior.
- **L7 proxy:** configure routes, verify correct backend selection, safe retries, `503` on no upstreams, and circuit-breaker transitions.
