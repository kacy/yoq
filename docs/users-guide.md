# yoq user's guide

this is a guide to how yoq works under the hood. it's not a CLI tutorial — it's an explanation of the internals for people evaluating, adopting, or contributing to the project.

---

## containers

yoq runs containers directly on Linux kernel primitives. there's no daemon — the `yoq` binary forks the container process itself.

### namespaces

each container gets its own set of namespaces via `clone3()`:

- **PID** — the container's init process is PID 1 inside the namespace
- **NET** — private network stack with its own interfaces and routing
- **MNT** — isolated mount table for overlayfs
- **UTS** — separate hostname
- **IPC** — separate shared memory and semaphores
- **USER** — UID/GID mapping for rootless operation
- **CGROUP** — dedicated cgroup subtree

### filesystem

the container root is an overlayfs mount: image layers are the read-only lower dirs, with a writable upper dir on top. `pivot_root` switches into this merged view. inside, yoq mounts `/proc`, `/dev`, `/sys`, and `/tmp`. symlinks in overlay paths are rejected to prevent escape.

### resource limits

cgroups v2 enforces:
- **CPU weight** — proportional CPU scheduling
- **memory max** — hard limit (default 512MB, minimum 4MB)
- **pids max** — process count limit (default 4096, minimum 1)

PSI (pressure stall information) metrics are read from cgroups for resource monitoring.

### security

- **seccomp** — classic BPF syscall allowlist. only approved syscalls can execute.
- **capabilities** — dropped to a minimal set: CHOWN, DAC_OVERRIDE, NET_RAW, NET_BIND_SERVICE, SETUID/SETGID, KILL.
- **no_new_privs** — prevents privilege re-escalation after exec.

### lifecycle

containers follow a simple state machine: create → start → running → stop → removed.

yoq supervises the container process, captures stdout/stderr through pipes for `yoq logs`, and handles restart policies (none, always, on_failure). `yoq exec` runs additional commands inside a running container by entering its namespaces.

---

## images

### OCI distribution

yoq speaks the OCI distribution protocol. `yoq pull` downloads images from any compliant registry. `yoq push` uploads them. bearer token auth, multi-arch manifests (resolves to linux/amd64), and both Docker and OCI media types are supported.

### content-addressable store

blobs live at `~/.local/share/yoq/blobs/sha256/<hex>`. writes are atomic (write to temp file, then rename). identical content always maps to the same path, giving automatic deduplication across images that share layers.

size limits prevent memory exhaustion: 10MB for manifests, 512MB for individual blobs.

### build engine

the build engine supports Dockerfile and a TOML alternative. all major Dockerfile directives are implemented, including multi-stage builds.

the key difference from Docker's build cache: yoq caches by content hash, not instruction order. reordering Dockerfile instructions doesn't invalidate the cache.

---

## networking

### bridge and IPs

yoq creates a `yoq0` bridge on first use. each container gets a veth pair: one end on the bridge, the other moved into the container namespace as `eth0`. IPs are allocated from `10.42.0.0/16` and tracked in SQLite.

### DNS

a userspace DNS resolver listens on `10.42.0.1:53`. it answers A record queries for service names from an in-memory registry (256 entries, no heap allocation). unknown names are forwarded upstream.

an eBPF TC program intercepts DNS queries on the bridge for fast-path resolution — cache hits are answered entirely in kernel space, misses fall through to userspace.

### load balancing

an eBPF program on the bridge implements FNV-1a consistent hashing for load balancing. a conntrack map (5-tuple → selected backend) ensures existing connections stick to the same backend. reverse SNAT on egress handles return traffic.

### network policy

eBPF-based allow/deny rules between services. policies are stored in SQLite and loaded into BPF maps at runtime.

### WireGuard hub-and-spoke

for multi-node clusters, WireGuard tunnels provide encrypted cross-node connectivity.

- **servers are hubs** — they enable IP forwarding and include all container subnets in their WireGuard allowed-ips
- **agents are spokes** — they connect only to servers, not to each other

this avoids O(n²) peer configurations. agent join/leave is a single-peer operation on the server side. the overlay uses `10.40.0.0/24`, with each node's containers in `10.42.{node_id}.0/24`.

key exchange happens during the `yoq join` handshake. service discovery works transparently across nodes.

### eBPF programs

7 BPF programs handle dataplane operations in kernel space:

| program | function |
|---------|----------|
| `lb.c` | load balancing with FNV-1a consistent hashing and conntrack |
| `dns_intercept.c` | kernel-space DNS resolution |
| `policy.c` | network policy enforcement |
| `metrics.c` | per-service packet counting |
| `port_map.c` | XDP port mapping |
| `gpu_prio.c` | GPU traffic prioritization |
| `storage_metrics.c` | storage I/O metrics |

---

## service orchestration

### manifests

TOML manifests define applications with five section types:

- `[service.*]` — long-running processes
- `[worker.*]` — one-shot tasks (e.g. database migrations)
- `[cron.*]` — recurring scheduled tasks
- `[volume.*]` — named storage volumes
- `[training.*]` — distributed GPU training jobs

services start in dependency order (topological sort). `yoq validate` checks for circular, self, and unknown dependencies.

### health checks

HTTP, TCP, gRPC, or exec probes run at configurable intervals. gRPC probes currently validate the HTTP/2 preface exchange on the configured port. health state is stored in a fixed-size registry (64 services, mutex-protected). the orchestrator and DNS resolver read health state to gate traffic.

### gRPC routing

gRPC services can use the HTTP routing listener through prior-knowledge HTTP/2 (h2c) passthrough. unary requests and streaming RPC traffic are forwarded end to end, including client `DATA` frames, server `DATA` frames, and trailing `HEADERS`. if the routed host also has a matching `tls.domain`, the TLS terminator can negotiate ALPN `h2` and forward that HTTPS traffic into the same routing path.

HTTP routes can now narrow traffic by method as well as host, path, and exact headers. use `match_methods = ["GET", "POST"]` on `http_proxy` or named `http_routes` entries when you need separate read/write routing policy without splitting the service definition.

For weighted routes, `GET /v1/services/<name>/proxy-routes` and `GET /v1/status?mode=service_discovery` now expose both aggregate route traffic and per-backend traffic breakdowns, which makes canary and cutover behavior visible without switching to Prometheus first.

current limits:

- the plaintext routing listener still speaks prior-knowledge `h2c`; TLS/ALPN HTTP/2 support comes through the TLS terminator for routed hosts with matching `tls.domain`

### TLS and ACME

services can enable TLS termination with `[service.<name>.tls]`. when `acme = true`, yoq provisions and renews certificates with ACME HTTP-01 validation through the built-in TLS proxy on ports 443 and 80.

current limits:

- ACME currently uses HTTP-01 only
- the target host must be reachable on port 80 during provision and renewal
- standalone `yoq cert provision` and `yoq cert renew` currently require `--email`

### rolling updates

deployment history is tracked in SQLite. updates proceed incrementally — if health checks fail during a rollout, yoq automatically rolls back.

### dev mode

`yoq up --dev` bind-mounts source directories and watches for file changes via inotify. changed files trigger a container restart with 500ms debounce. logs are multiplexed with colored service name prefixes.

### alerting

services can define threshold-based alerts on CPU, memory, restart count, p99 latency, and error rate. when a metric exceeds its threshold for consecutive checks, the configured webhook is fired.

---

## clustering

### role separation

- **server nodes** run Raft consensus, the API server, and the scheduler
- **agent nodes** run gossip and container workloads

the consensus group stays small while the agent pool scales independently.

### Raft

a pure state machine implementation — no I/O in the core algorithm. all side effects are described as `Action` values that the caller executes. this makes the algorithm fully testable without mocks.

- election timeout: 1.5-3s (randomized)
- heartbeat: 1s
- log persistence: SQLite WAL mode
- snapshot: InstallSnapshot RPC for lagging followers

### gossip

SWIM (Scalable Weakly-consistent Infection-style Membership) protocol for failure detection. runs over UDP. nodes probe each other directly (ping) and indirectly (ping-req through a third node). protocol updates piggyback on protocol messages — no extra round trips.

the implementation is a pure state machine like Raft: `tick()`, `handleMessage()`, `drainActions()`.

### scheduler

bin-packing placement: scores agents by free CPU + memory, assigns containers to the best-fit agent. draining and offline agents are skipped.

### agents

agents register via HTTP, then heartbeat every 5s reporting capacity. they pull assignments, download images, and start containers locally. WireGuard tunnels are set up on join.

if the leader changes, agents follow automatically — heartbeat responses include leader hints.

### rolling upgrades

to upgrade a cluster without downtime:
1. drain and upgrade agents (one at a time or in batches)
2. upgrade non-leader servers one at a time
3. trigger leader step-down (`POST /cluster/step-down`), then upgrade the old leader

agents automatically follow the new leader.

---

## GPU and training

### detection

yoq discovers NVIDIA GPUs via `/dev/nvidia*` device nodes, the NVML shared library (`dlopen`), and procfs/sysfs fallback. reports GPU count, model, VRAM, and driver version.

### passthrough

GPU devices and NVIDIA libraries are bind-mounted into containers. cgroup device rules allow access. the container sees the GPU as if it were on the host.

### gang scheduling

distributed training workloads use all-or-nothing scheduling: either all requested ranks get placed, or none do. the scheduler is topology-aware — it prefers placing ranks on nodes with direct GPU interconnects.

### MIG and MPS

- **MIG** (Multi-Instance GPU) — partitions a single GPU into isolated instances for sharing
- **MPS** (Multi-Process Service) — enables concurrent GPU access from multiple containers

### InfiniBand and NCCL

yoq detects InfiniBand HCAs, generates NCCL topology XML for optimal GPU-NIC affinity, and injects NCCL environment variables into training containers (`MASTER_ADDR`, `MASTER_PORT`, `WORLD_SIZE`, `RANK`, `LOCAL_RANK`).

### health monitoring

periodic NVML checks of GPU temperature, ECC errors, and utilization. feeds into the alerting system.

### training jobs

training jobs follow a state machine: pending → scheduling → running → paused → completed/failed/stopped.

- **checkpoints:** configurable interval (default 1800s) and retention (default 5)
- **fault tolerance:** spare ranks, auto-restart (up to 10 by default), resume from latest checkpoint
- **data:** dataset path, sharding strategy, optional preprocessing pipeline
- **resources:** CPU, memory, and InfiniBand requirements per rank

### CLI

- `yoq gpu topo [--json]` — show GPU topology (PCIe, NVLink, InfiniBand)
- `yoq gpu bench [--gpus N] [--size BYTES] [--iterations N]` — GPU-to-GPU bandwidth benchmarks
- `yoq train start|status|stop|pause|resume|scale|logs <name>` — manage training jobs

---

## storage

### S3-compatible gateway

a filesystem-backed S3-compatible API. supports bucket CRUD, object HEAD/GET/PUT/DELETE, and multipart uploads. objects are stored under `~/.local/share/yoq/s3/`.

### volume drivers

four drivers provide storage backends for container volumes:

| driver | description |
|--------|-------------|
| `local` | managed by yoq (default) |
| `host` | bind-mount a host directory |
| `nfs` | mount an NFS share |
| `parallel` | mount a parallel filesystem (Lustre, GPFS) |

see the [manifest spec](manifest-spec.md#volumes) for configuration details.

---

## security

### process

each container runs in isolated namespaces with minimal capabilities, seccomp syscall filtering, and `no_new_privs`.

### filesystem

overlayfs with `pivot_root`. dangerous bind mount targets (`/etc`, `/root`, `/proc`, `/sys`) are blocked. symlinks in overlay paths are rejected.

### network

containers get private IPs on an internal bridge. outbound traffic is NATed. inbound requires explicit port mapping.

### secrets

encrypted at rest with XChaCha20-Poly1305. mounted as files or injected as environment variables. rotation doesn't require container restart.

### API

bearer token authentication with constant-time comparison. tokens are generated on first server start and stored at `~/.local/share/yoq/api_token`.

### cluster

HMAC-SHA256 authentication on all cluster messages, derived from the join token. constant-time comparison prevents timing side-channels. WireGuard encrypts all cross-node communication with keys exchanged during join.

---

## observability

### metrics

eBPF programs collect per-service and per-service-pair network metrics (packet counts, bytes). PSI metrics from cgroups track CPU, memory, and I/O pressure.

- `yoq metrics [service]` — per-service metrics
- `yoq metrics --pairs` — service-to-service metrics

for service discovery and HTTP routing, the API also exposes two deeper observability surfaces:

- `GET /v1/status?mode=service_discovery` — JSON snapshot of discovery state, audit and health checker state, L7 proxy status, listener/control-plane status, and steering readiness
- `GET /v1/metrics?format=prometheus` — Prometheus text format for the same discovery surface plus per-service counters and gauges

`mode=service_rollout` remains accepted as a compatibility alias.

the Prometheus endpoint includes discovery-wide and per-service series such as:

- reconcile requests, successes, failures, and most recent reconcile duration
- DNS interceptor and load balancer sync failures
- health check scheduled/completed/stale totals and most recent health check latency
- endpoint flap totals and current service health status
- L7 proxy request/response/retry/failure counters and listener/control-plane state
- route/backend counters for weighted HTTP routing, exposed as `yoq_service_l7_proxy_route_*`

the status JSON is the better debugging view when you want to inspect discovery and routing state directly. in particular, `l7_proxy.sample_routes` shows the active route definitions and `l7_proxy.sample_route_traffic` shows recent counters by route and selected backend service. the Prometheus endpoint is the better integration point for scraping, dashboards, and alerting.

### alerting

threshold-based alerts on CPU, memory, restart count, p99 latency, and error rate. webhook notifications when thresholds are exceeded.

### doctor

`yoq doctor` runs 7 pre-flight checks: kernel version (≥6.1), cgroup-v2, eBPF, GPU, WireGuard, InfiniBand, and disk space. each check reports pass/warn/fail. GPU, WireGuard, and InfiniBand return `warn` when hardware is absent since these are optional.

---

## operational reference

### data directory

all yoq state lives under `~/.local/share/yoq/`:
- `yoq.db` — SQLite database (containers, images, secrets, policies, history)
- `blobs/sha256/` — content-addressable image store
- `s3/` — S3 gateway object storage
- `api_token` — API bearer token

### backup and restore

- `yoq backup [--output path]` — uses SQLite Online Backup API, safe while running
- `yoq restore <path>` — validates schema version before replacing the active database

volume data is not included in backups.

### ports

| port | protocol | service |
|------|----------|---------|
| 7700 | TCP | API server |
| 9700 | TCP | Raft consensus |
| 9800 | UDP | gossip protocol |
| 51820 | UDP | WireGuard overlay |

### requirements

- Linux kernel 6.1+
- Zig 0.15.2 (for building from source)
