# architecture

yoq folds container runtime, orchestration, networking, clustering, and TLS into one Linux binary. the goal is to keep the whole stack inspectable without stitching together several separate systems.

written in Zig, targeting Linux kernel 6.1+.

## overview

```
                     ┌──────────────┐
                     │   CLI / API  │
                     └──────┬───────┘
                            │
              ┌─────────────┼─────────────┐
              │             │             │
        ┌─────┴─────┐ ┌────┴────┐ ┌──────┴──────┐
        │  manifest  │ │ runtime │ │   cluster   │
        │ orchestrator│ │container│ │  raft/agent │
        └─────┬─────┘ └────┬────┘ └──────┬──────┘
              │             │             │
    ┌─────────┼─────────────┼─────────────┼──────────────┐
    │         │             │             │              │
┌───┴───┐ ┌──┴──┐   ┌──────┴──────┐ ┌────┴────┐ ┌──────┴──────┐
│ build │ │image│   │  networking │ │  state  │ │     gpu     │
│engine │ │store│   │ ebpf/bridge │ │ sqlite  │ │  training   │
└───────┘ └─────┘   └─────────────┘ └────┬────┘ └─────────────┘
                                         │
                              ┌──────────┼──────────┐
                              │          │          │
                           ┌──┴──┐  ┌────┴────┐ ┌──┴───┐
                           │ tls │  │ storage │ │alerts│
                           │acme │  │s3/volume│ │      │
                           └─────┘  └─────────┘ └──────┘
```

data flows top-down: CLI commands dispatch to subsystems, which use shared state (SQLite) and networking primitives (eBPF, netlink). the cluster layer replicates state across nodes via Raft.

## subsystems

### runtime (`src/runtime/`)

container isolation using Linux primitives directly — no daemon, no shim.

**container lifecycle:** create → start → running → stop → removed. each container gets its own set of namespaces (PID, NET, MNT, UTS, IPC, USER, CGROUP) created via `clone3()`. the child process's stdio is captured through pipes for log collection.

**filesystem:** overlayfs with image layers as lower dirs, a writable upper dir, and pivot_root into the merged view. `/proc`, `/dev`, `/sys`, `/tmp` are mounted inside. symlinks in overlay paths are rejected for security.

**resource limits:** cgroups v2 with configurable CPU weight, memory max (default 512MB), and pids max (default 4096). safe minimums are enforced (4MB memory, 1 process). PSI (pressure stall information) metrics are read from cgroups for monitoring.

**security:** seccomp filters (classic BPF) restrict syscalls to a safe allowlist. capabilities are dropped to a minimal set (CHOWN, DAC_OVERRIDE, NET_RAW, NET_BIND_SERVICE, SETUID/SETGID, KILL). `no_new_privs` prevents re-escalation.

key files:
- `container.zig` — lifecycle and config types
- `namespaces.zig` — clone3, UID/GID mapping
- `cgroups.zig` — resource limits, PSI metrics
- `filesystem.zig` — overlayfs, pivot_root
- `security.zig` — seccomp, capabilities
- `process.zig` — signal handling, wait
- `logs.zig` — stdout/stderr capture

### image (`src/image/`)

OCI image management — pull from any registry, content-addressable storage, layer deduplication.

**store:** blobs live at `~/.local/share/yoq/blobs/sha256/<hex>`. writes are atomic (temp file, then rename). same content always maps to the same path, giving automatic deduplication across images.

**registry client:** speaks the OCI distribution protocol over HTTPS. handles bearer token auth, multi-arch manifests (resolves to linux/amd64), and both Docker and OCI media types. size limits prevent memory exhaustion (10MB manifests, 512MB blobs).

**layers:** tar.gz extraction with automatic format detection (gzip, bzip2, xz, zstd). layers are cached by digest — shared across images that use the same base.

key files:
- `spec.zig` — OCI types (Manifest, ImageConfig, Descriptor)
- `store.zig` — content-addressable blob storage
- `registry.zig` — registry pull/push client
- `layer.zig` — layer extraction and dedup
- `commands.zig` — pull, push, images, rmi, prune, inspect

### networking (`src/network/`)

container networking with eBPF for service discovery and load balancing.

**bridge:** a `yoq0` bridge is created on first use. each container gets a veth pair: one end on the bridge, one moved into the container namespace as `eth0`. IPs are allocated from `10.42.0.0/16` and tracked in SQLite.

**DNS:** a userspace DNS resolver listens on `10.42.0.1:53`. it answers A record queries for service names from an in-memory registry (256 entries, no heap allocation). unknown names are forwarded to the upstream resolver. an eBPF TC program intercepts DNS queries on the bridge for fast-path resolution — cache hits are answered entirely in kernel space, misses fall through to userspace.

**load balancing:** an eBPF program on the bridge implements FNV-1a consistent hashing for load balancing with connection affinity. a conntrack map (5-tuple → selected backend) ensures existing connections stick to the same backend. reverse SNAT on egress handles return traffic.

**network policy:** eBPF-based allow/deny rules between services. policies are stored in SQLite and loaded into BPF maps.

**cross-node:** WireGuard hub-and-spoke tunnels are set up automatically when nodes join a cluster. server nodes act as hubs — they enable IP forwarding and include all container subnets in their WireGuard allowed-ips. agent nodes are spokes — they connect only to servers, not to each other. this avoids O(n²) peer configurations: agent join/leave is a single-peer operation on the server side. key exchange happens during the join handshake. the overlay uses `10.40.0.0/24`, with each node's containers in `10.42.{node_id}.0/24`. service discovery works transparently across nodes.

**eBPF programs:** 7 BPF programs in `bpf/`:
- `lb.c` — load balancing with FNV-1a consistent hashing and conntrack
- `dns_intercept.c` — kernel-space DNS resolution
- `policy.c` — network policy enforcement
- `metrics.c` — per-service packet counting
- `port_map.c` — XDP port mapping
- `gpu_prio.c` — GPU traffic prioritization
- `storage_metrics.c` — storage I/O metrics

key files:
- `bridge.zig` — bridge/veth management via netlink
- `dns.zig` — userspace DNS resolver + service registry
- `ebpf.zig` — BPF program loading (no libbpf dependency)
- `nat.zig` — iptables NAT and port mapping
- `wireguard.zig` — WireGuard hub-and-spoke setup

### build (`src/build/`)

image building with content-hash caching.

**Dockerfile parser:** supports FROM, RUN, COPY, ADD, ENV, EXPOSE, ENTRYPOINT, CMD, WORKDIR, ARG, LABEL, VOLUME, SHELL, HEALTHCHECK, STOPSIGNAL, ONBUILD. handles line continuations and multi-stage builds (COPY --from).

**build engine:** each step produces a layer cached by content hash — not by layer order. this means reordering instructions doesn't invalidate the cache (unlike Docker). RUN steps mount an overlay and execute in a container. COPY steps create a new layer from the build context. ONBUILD triggers stored in image config are executed when the image is used as a base.

**declarative format:** a TOML-based build manifest as an alternative to Dockerfile, with automatic stage dependency resolution.

key files:
- `dockerfile.zig` — parser
- `engine.zig` — build execution, caching
- `context.zig` — build context file hashing
- `manifest.zig` — TOML build format
- `commands.zig` — `build` CLI

### manifest (`src/manifest/`)

application management — the compose/orchestrator/control-plane layer.

**format:** TOML manifests define `[service.*]`, `[worker.*]`, `[cron.*]`, `[volume.*]`, and `[training.*]` sections. the loader validates dependencies, expands environment variables (`${VAR:-default}`), and normalizes the result into one canonical `ApplicationSpec`.

**canonical app model:** local `yoq up` and remote `yoq up --server` both derive the same `ApplicationSpec`, then one `ReleasePlan`, then execute through the same apply/report model. this is the basis of the app-first control plane.

**orchestrator:** starts and stops services respecting dependency order. reconciles running state against desired state. handles restart policies (none, always, on_failure).

**health checks:** a single checker thread polls HTTP, TCP, gRPC, or exec probes at configurable intervals. health state is stored in a fixed-size registry (64 services, mutex-protected) that the orchestrator and DNS resolver read to gate traffic.

**release model:** app release rows in SQLite store the canonical config snapshot, manifest hash, trigger metadata, rollout state, rollout control state, progress counts, failure details, per-target rollout state, and rollout checkpoint data. local and remote app status/history/rollback all project from that same release data.

**rollouts:** service replacement applies use rollout policy carried in the app snapshot. the current engine supports `rolling`, `canary`, and `blue_green` execution semantics, readiness-gated cutover, `pause` / `resume` / `cancel`, failure-action rollback, and checkpoint-aware recovery. services are the only workload kind that automatically roll out on apply.

**dev mode:** `yoq up --dev` bind-mounts source directories and watches for file changes via inotify. changed files trigger a container restart with 500ms debounce. colored log output is multiplexed with service name prefixes.

**workload parity:** workers, crons, and training jobs now live in the same canonical app snapshot and release history as services:

- workers are stored in the current app release and run on demand
- crons are registered from the current app release and restored on rollback
- training definitions are stored in the app release, while training runtime state remains a separate lifecycle

**cron scheduling:** periodic tasks run at configurable intervals (e.g., `every = "1h"`), with the active cron set derived from the current app release.

**alerting:** services can define alert thresholds (CPU, memory, restart count, p99 latency, error rate) with webhook notifications. when a metric exceeds its threshold for consecutive checks, the configured webhook is fired.

key files:
- `spec.zig` — Service, Worker, Cron, Volume, TrainingJob, AlertSpec types
- `app_spec.zig` — canonical `ApplicationSpec`
- `release_plan.zig` — app release snapshot and manifest hash
- `apply_release.zig` — shared apply executor, report, and rollout projection
- `local_apply_backend.zig` — local fresh/replacement apply backend
- `loader.zig` — TOML parser, dependency validation, topo sort
- `orchestrator.zig` — start/stop/reconcile
- `health.zig` — health check engine
- `update.zig` — rolling updates, rollback
- `cron_scheduler.zig` — periodic task execution
- `training.zig` — training job lifecycle controller
- `commands.zig` — up, down, rollback, history, train

### cluster (`src/cluster/`)

multi-node orchestration via Raft consensus and SWIM gossip.

**role separation:** the cluster has two node types. server nodes run Raft consensus, the API server, and the scheduler. agent nodes run only the gossip protocol and container workloads. this keeps the consensus group small while allowing the agent pool to scale independently.

**Raft:** a pure state machine implementation with no I/O. all side effects are described as `Action` values (send vote request, append entries, commit, etc.) that the caller executes. this makes the core algorithm testable without mocking. election timeout is 1.5-3s (randomized), heartbeat at 1s.

**gossip:** SWIM (Scalable Weakly-consistent Infection-style Membership) protocol for failure detection. nodes probe each other directly (ping) and indirectly (ping-req through a third node) to detect failures without centralized health checking. protocol updates (joins, leaves, state changes) are piggybacked on protocol messages for efficient dissemination without extra round trips. gossip runs over UDP for protocol simplicity and lower overhead. the implementation is a pure state machine like raft — `tick()`, `handleMessage()`, `drainActions()`.

**log replication:** the Raft log is persisted in SQLite (WAL mode for crash safety). committed entries are applied to a replicated state machine that updates the shared SQLite database. lagging followers receive snapshots via InstallSnapshot RPC.

**scheduler:** bin-packing placement as a pure function: given resource requests and agent capacities, it scores agents by free resources (CPU + memory) and assigns containers. draining and offline agents are skipped.

**agents:** worker nodes register with the server via HTTP, then heartbeat every 5s reporting capacity. they pull assignments, download images, and start containers using the local runtime. WireGuard tunnels are set up on join for encrypted cross-node networking.

**app-first control plane:** the canonical cluster write path is `POST /apps/apply`. cluster routes parse app snapshots into the same release model used locally, then execute through the cluster scheduling backend. app-scoped reads (`/apps`, `/apps/{name}/status`, `/apps/{name}/history`) and writes (`/apps/{name}/rollback`, rollout control, worker run, training control) all project from that same release/store layer.

**rollout execution:** clustered service rollouts are readiness-gated and checkpoint-aware. the server batches assignments by rollout policy, waits for assignment readiness and agent-side service health where configured, cuts over only after readiness succeeds, records per-target rollout state, and can recover active rollouts in place after restart or leadership handoff.

**HMAC auth:** all cluster messages (Raft RPCs, gossip protocol) are authenticated with HMAC-SHA256. the key is derived from the join token. token comparison uses constant-time operations to prevent timing side-channels and avoids leaking token length.

**connection pool:** the transport layer reuses TCP connections between nodes instead of opening a new connection per RPC. this reduces latency and file descriptor churn under load.

key files:
- `raft.zig` — pure Raft state machine
- `raft_types.zig` — protocol message types
- `gossip.zig` — SWIM gossip failure detection
- `log.zig` — SQLite-backed persistent log
- `state_machine.zig` — apply committed entries
- `scheduler.zig` — bin-packing placement
- `agent.zig` — worker node agent
- `node.zig` — server node management (integrates raft + gossip)
- `transport.zig` — TCP RPC (with connection pooling) and UDP gossip
- `commands.zig` — serve, init-server, join, nodes, drain

### state (`src/state/`)

persistent storage for all yoq state.

**SQLite:** the database at `~/.local/share/yoq/yoq.db` stores containers, images, service names, secrets, network policies, app releases, rollout progress, rollout checkpoints, training runtime state, and deployment history. schema migrations run on startup. in cluster mode, the database is replicated via Raft.

**secrets:** encrypted at rest with XChaCha20-Poly1305. can be mounted as files or injected as environment variables. rotation doesn't require container restart.

**backup/restore:** uses the SQLite Online Backup API (`sqlite3_backup_init`/`step`/`finish`), which is safe to run while the server is running. restores validate the schema version before replacing the active database. volume data is not included in backups — only the SQLite state.

key files:
- `store.zig` — container/image CRUD operations
- `schema.zig` — database schema and migrations
- `secrets.zig` — encrypted secret storage
- `backup.zig` — online backup and restore
- `commands.zig` — secret, backup, restore CLI

### GPU (`src/gpu/`)

GPU detection, passthrough, scheduling, and distributed training support.

**detection:** discovers NVIDIA GPUs via `/dev/nvidia*` device nodes, NVML shared library (`dlopen`), and procfs/sysfs fallback. reports GPU count, model, VRAM, driver version.

**passthrough:** bind-mounts GPU device nodes and NVIDIA libraries into containers. sets cgroup device rules to allow access. the container sees the GPU as if it were on the host.

**gang scheduling:** all-or-nothing scheduling for distributed training — either all requested ranks get placed, or none do. topology-aware: prefers placing ranks on nodes with direct GPU interconnects.

**MIG/MPS:** supports NVIDIA Multi-Instance GPU (MIG) partitioning for sharing a single GPU across containers, and Multi-Process Service (MPS) for concurrent GPU access.

**InfiniBand/NCCL:** detects InfiniBand HCAs, generates NCCL topology XML for optimal GPU-NIC affinity, and injects NCCL environment variables into training containers.

**health monitoring:** periodic checks of GPU temperature, ECC errors, and utilization via NVML. feeds into the alerting system.

**CLI:** `yoq gpu topo` shows GPU topology (PCIe, NVLink, InfiniBand). `yoq gpu bench` runs GPU-to-GPU bandwidth benchmarks.

key files:
- `detect.zig` — GPU discovery
- `passthrough.zig` — device bind-mount and cgroup rules
- `scheduler.zig` — gang scheduling
- `mig.zig` — MIG partitioning
- `mps.zig` — MPS sharing
- `mesh.zig` — InfiniBand/NCCL topology
- `health.zig` — temperature, ECC, utilization monitoring
- `commands.zig` — gpu topo, gpu bench CLI

### training (`src/manifest/training.zig`)

distributed training job orchestration.

**lifecycle:** TrainingJobState machine: pending → scheduling → running → paused → completed/failed/stopped. the TrainingController manages transitions and tracks per-rank status.

**multi-rank:** each training job spawns one container per GPU (rank). NCCL environment variables (`MASTER_ADDR`, `MASTER_PORT`, `WORLD_SIZE`, `RANK`, `LOCAL_RANK`) are injected automatically. gang scheduling ensures all ranks start together.

**checkpoints:** configurable checkpoint interval and retention. the controller persists checkpoint metadata to SQLite for resume-after-failure.

**fault tolerance:** spare ranks can be held in reserve. failed ranks auto-restart up to a configurable limit. the job resumes from the latest checkpoint.

### storage (`src/storage/`)

S3-compatible object storage and volume management.

**S3 gateway:** a filesystem-backed S3-compatible API. supports bucket CRUD, object HEAD/GET/PUT/DELETE, and multipart uploads. objects are stored under `~/.local/share/yoq/s3/`.

**volume drivers:** four drivers (local, host, NFS, parallel) provide storage backends for container volumes. see the [manifest spec](manifest-spec.md#volumes) for configuration.

key files:
- `s3.zig` — S3 API routes and bucket/object operations
- `s3_xml.zig` — S3 XML response generation
- `metrics.zig` — storage I/O metrics

### doctor (`src/lib/doctor.zig`)

pre-flight system readiness checks. `yoq doctor` runs 7 checks and reports pass/warn/fail for each:

1. **kernel** — Linux kernel ≥ 6.1
2. **cgroup-v2** — cgroups v2 mounted and writable
3. **ebpf** — BPF program loading support
4. **gpu** — NVIDIA GPU and driver availability
5. **wireguard** — WireGuard kernel module
6. **infiniband** — InfiniBand HCA detection
7. **disk-space** — sufficient free disk space

GPU, WireGuard, and InfiniBand checks return `warn` (not `fail`) when hardware is absent, since these are optional features.

### API (`src/api/`)

HTTP management API for local and remote control.

**server:** a blocking HTTP 1.1 server with thread pool. listens on localhost for single-node, or a specified interface for cluster mode. default port 7700. bearer token authentication with constant-time comparison.

**routes:** REST endpoints for containers, images, cluster status, agents, metrics, and app releases. the primary app-first surfaces are:

- `POST /apps/apply`
- `GET /apps`
- `GET /apps/{name}/status`
- `GET /apps/{name}/history`
- `POST /apps/{name}/rollback`
- `POST /apps/{name}/rollout/pause|resume|cancel`
- `POST /apps/{app}/workers/{name}/run`
- `POST /apps/{app}/training/{name}/start|stop|pause|resume|scale`
- `GET /apps/{app}/training/{name}/status|logs`

the CLI uses those routes for remote operations. local operations use the same app/release model directly against the runtime and store layer.

key files:
- `http.zig` — HTTP 1.1 parser (zero-copy)
- `routes.zig` — endpoint dispatch + auth
- `server.zig` — socket listener + thread pool

### TLS (`src/tls/`)

certificate management and TLS termination.

**ACME:** Let's Encrypt-compatible client implementing HTTP-01 challenge validation. registers accounts, creates orders, serves challenge tokens on port 80, polls authorization and order state, and downloads signed certificates.

**TLS proxy:** a reverse proxy that terminates TLS 1.3 (AES-256-GCM). routes connections based on SNI (Server Name Indication) extracted from the ClientHello message.

**certificate store:** persists certificates by domain with expiry tracking. the TLS proxy checks for expiring ACME certificates and renews them in place.

key files:
- `acme.zig` — ACME client
- `proxy.zig` — TLS 1.3 reverse proxy
- `sni.zig` — SNI extraction
- `cert_store.zig` — certificate persistence
- `commands.zig` — cert install, provision, renew, list, rm

### shared libraries (`src/lib/`)

- `toml.zig` — minimal TOML parser (tables, strings, integers, booleans, arrays; max 64 nesting depth)
- `json_output.zig` — JSON writer for `--json` output (8KB buffer, no allocations)
- `json_helpers.zig` — JSON encoding for API responses
- `cli.zig` — output helpers, `OutputMode` (human/json)
- `log.zig` — structured logging
- `paths.zig` — XDG data directory management (`~/.local/share/yoq/`)
- `crypto.zig` — hashing, key generation
- `syscall.zig` — low-level syscall wrappers
- `sql.zig` — SQL escaping for raft proposals
- `doctor.zig` — system readiness checks

## design decisions

**no async runtime.** yoq uses io_uring + thread pool instead of async/await. this is simpler and more efficient for the I/O patterns involved (container lifecycle, network setup, file operations).

**explicit allocators.** every subsystem receives its allocator explicitly. arena allocators per container ensure predictable cleanup on container removal — no garbage, no leaks.

**zero external dependencies.** HTTP server, JSON/TOML parsing, Raft consensus, TLS, ACME — all implemented in Zig. the only runtime dependency is the Linux kernel (6.1+). the binary is statically linked.

**pure Raft.** the Raft state machine has no I/O. it takes inputs (ticks, RPCs) and returns actions (send messages, commit entries). the caller handles all networking and persistence. this makes the core algorithm fully testable without mocks.

**eBPF for dataplane.** DNS resolution, load balancing, port mapping, metrics collection, network policy enforcement, and GPU traffic prioritization all run as eBPF programs in kernel space. this replaces kube-proxy, CNI plugins, and service mesh sidecars with a handful of C programs totaling ~500 lines.

**fixed-size registries.** the DNS service registry (256 entries), health check registry (64 services), and BPF maps use fixed-size data structures. no heap allocation on the hot path — just array indexing.

**content-hash build cache.** build layer caching is keyed by content hash, not by instruction order. reordering Dockerfile instructions doesn't invalidate the cache (unlike Docker).

**SQLite for everything.** container state, image metadata, service names, secrets, network policies, deployment history, and Raft log all live in SQLite. in cluster mode, the database is replicated via Raft. no etcd, no separate state store.

**hub-and-spoke WireGuard.** server nodes are WireGuard hubs that forward inter-agent traffic. agents connect only to servers, avoiding O(n²) peer configurations. agent join/leave is a single-peer operation on the server side.

**app-first control plane.** manifests are normalized once into `ApplicationSpec`, then carried through `ReleasePlan`, apply execution, status/history, rollback, and remote `/apps/*` APIs. this removes the older split between local manifest execution and remote ad hoc deploy payloads.

**structured rollout state.** rollout behavior is driven by explicit fields rather than message text: lifecycle status, rollout state, rollout control state, target counts, failure details, per-target state, and checkpoints.

## security model

1. **process isolation:** each container runs in its own set of namespaces. capabilities are dropped to a minimal set. seccomp restricts available syscalls.

2. **filesystem isolation:** overlayfs with pivot_root. dangerous bind mount targets (`/etc`, `/root`, `/proc`, `/sys`) are blocked. symlinks in overlay paths are rejected.

3. **network isolation:** containers get private IPs on an internal bridge. outbound traffic is NATed. inbound traffic requires explicit port mapping.

4. **secrets:** encrypted at rest (XChaCha20-Poly1305). mounted as files or env vars — never stored in plain text.

5. **API auth:** bearer token authentication with constant-time comparison. tokens are generated on first server start.

6. **cluster transport:** HMAC-SHA256 authentication on all cluster messages (Raft RPCs, gossip protocol), derived from the join token. token comparison is constant-time and does not leak token length. WireGuard encryption for all cross-node communication with keys exchanged during the join handshake.
