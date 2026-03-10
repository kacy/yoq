# architecture

yoq is a single binary that replaces Docker + Kubernetes + Istio + Helm for most teams. it provides container isolation, image management, networking, service orchestration, clustering, and TLS — all without external dependencies.

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
    ┌─────────┼─────────────┼─────────────┼─────────┐
    │         │             │             │         │
┌───┴───┐ ┌──┴──┐   ┌──────┴──────┐ ┌────┴────┐ ┌─┴──┐
│ build │ │image│   │  networking │ │  state  │ │tls │
│engine │ │store│   │ ebpf/bridge │ │ sqlite  │ │acme│
└───────┘ └─────┘   └─────────────┘ └─────────┘ └────┘
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

**load balancing:** an eBPF program on the bridge implements round-robin load balancing with connection affinity. a conntrack map (5-tuple → selected backend) ensures existing connections stick to the same backend. reverse SNAT on egress handles return traffic.

**network policy:** eBPF-based allow/deny rules between services. policies are stored in SQLite and loaded into BPF maps.

**cross-node:** WireGuard mesh tunnels are set up automatically when nodes join a cluster. key exchange happens during the join handshake. service discovery works transparently across nodes.

key files:
- `bridge.zig` — bridge/veth management via netlink
- `dns.zig` — userspace DNS resolver + service registry
- `ebpf.zig` — BPF program loading (no libbpf dependency)
- `nat.zig` — iptables NAT and port mapping
- `wireguard.zig` — WireGuard mesh setup
- `bpf/dns_intercept.c` — kernel-space DNS resolution
- `bpf/lb.c` — load balancing with conntrack
- `bpf/policy.c` — network policy enforcement
- `bpf/port_map.c` — XDP port mapping
- `bpf/metrics.c` — per-service packet counting

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

multi-service application management — the docker-compose replacement.

**format:** TOML manifests define `[service.*]`, `[worker.*]`, `[cron.*]`, and `[volume.*]` sections. the loader validates dependencies, expands environment variables (`${VAR:-default}`), and returns services in topological (dependency) order.

**orchestrator:** starts and stops services respecting dependency order. reconciles running state against desired state. handles restart policies (none, always, on_failure).

**health checks:** a single checker thread polls HTTP, TCP, or exec probes at configurable intervals. health state is stored in a fixed-size registry (64 services, mutex-protected) that the orchestrator and DNS resolver read to gate traffic.

**rolling updates:** deployment history is tracked in SQLite. updates proceed incrementally with automatic rollback if health checks fail.

**dev mode:** `yoq up --dev` bind-mounts source directories and watches for file changes via inotify. changed files trigger a container restart with 500ms debounce. colored log output is multiplexed with service name prefixes.

**cron scheduling:** periodic tasks run at configurable intervals (e.g., `every = "1h"`).

key files:
- `spec.zig` — Service, Worker, Cron, Volume types
- `loader.zig` — TOML parser, dependency validation, topo sort
- `orchestrator.zig` — start/stop/reconcile
- `health.zig` — health check engine
- `update.zig` — rolling updates, rollback
- `cron_scheduler.zig` — periodic task execution
- `commands.zig` — up, down, rollback, history

### cluster (`src/cluster/`)

multi-node orchestration via Raft consensus and SWIM gossip.

**role separation:** the cluster has two node types. server nodes run Raft consensus, the API server, and the scheduler. agent nodes run only the gossip protocol and container workloads. this keeps the consensus group small while allowing the agent pool to scale independently.

**Raft:** a pure state machine implementation with no I/O. all side effects are described as `Action` values (send vote request, append entries, commit, etc.) that the caller executes. this makes the core algorithm testable without mocking. election timeout is 1.5-3s (randomized), heartbeat at 1s.

**gossip:** SWIM (Scalable Weakly-consistent Infection-style Membership) protocol for failure detection. nodes probe each other directly (ping) and indirectly (ping-req through a third node) to detect failures without centralized health checking. protocol updates (joins, leaves, state changes) are piggybacked on protocol messages for efficient dissemination without extra round trips. gossip runs over UDP for protocol simplicity and lower overhead. the implementation is a pure state machine like raft — `tick()`, `handleMessage()`, `drainActions()`.

**log replication:** the Raft log is persisted in SQLite (WAL mode for crash safety). committed entries are applied to a replicated state machine that updates the shared SQLite database. lagging followers receive snapshots via InstallSnapshot RPC.

**scheduler:** bin-packing placement as a pure function: given resource requests and agent capacities, it scores agents by free resources (CPU + memory) and assigns containers. draining and offline agents are skipped.

**agents:** worker nodes register with the server via HTTP, then heartbeat every 5s reporting capacity. they pull assignments, download images, and start containers using the local runtime. WireGuard tunnels are set up on join for encrypted cross-node networking.

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

**SQLite:** the database at `~/.local/share/yoq/yoq.db` stores containers, images, service names, secrets, network policies, and deployment history. schema migrations run on startup. in cluster mode, the database is replicated via Raft.

**secrets:** encrypted at rest with XChaCha20-Poly1305. can be mounted as files or injected as environment variables. rotation doesn't require container restart.

key files:
- `store.zig` — container/image CRUD operations
- `schema.zig` — database schema and migrations
- `secrets.zig` — encrypted secret storage

### API (`src/api/`)

HTTP management API for local and remote control.

**server:** a blocking HTTP 1.1 server with thread pool. listens on localhost for single-node, or a specified interface for cluster mode. default port 7700. bearer token authentication with constant-time comparison.

**routes:** REST endpoints for containers, images, cluster status, agents, metrics, and deployments. the CLI talks to the API server for remote operations; local operations use the runtime directly.

key files:
- `http.zig` — HTTP 1.1 parser (zero-copy)
- `routes.zig` — endpoint dispatch + auth
- `server.zig` — socket listener + thread pool

### TLS (`src/tls/`)

certificate management and TLS termination.

**ACME:** full Let's Encrypt client implementing HTTP-01 challenge validation. registers accounts, creates orders, serves challenge tokens on port 80, and downloads signed certificates.

**TLS proxy:** a reverse proxy that terminates TLS 1.3 (AES-256-GCM). routes connections based on SNI (Server Name Indication) extracted from the ClientHello message.

**certificate store:** persists certificates by domain with expiry tracking and auto-renewal on startup.

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

## design decisions

**no async runtime.** yoq uses io_uring + thread pool instead of async/await. this is simpler and more efficient for the I/O patterns involved (container lifecycle, network setup, file operations).

**explicit allocators.** every subsystem receives its allocator explicitly. arena allocators per container ensure predictable cleanup on container removal — no garbage, no leaks.

**zero external dependencies.** HTTP server, JSON/TOML parsing, Raft consensus, TLS, ACME — all implemented in Zig. the only runtime dependency is the Linux kernel (6.1+). the binary is statically linked.

**pure Raft.** the Raft state machine has no I/O. it takes inputs (ticks, RPCs) and returns actions (send messages, commit entries). the caller handles all networking and persistence. this makes the core algorithm fully testable without mocks.

**eBPF for dataplane.** DNS resolution, load balancing, port mapping, metrics collection, and network policy enforcement all run as eBPF programs in kernel space. this replaces kube-proxy, CNI plugins, and service mesh sidecars with a handful of C programs totaling ~500 lines.

**fixed-size registries.** the DNS service registry (256 entries), health check registry (64 services), and BPF maps use fixed-size data structures. no heap allocation on the hot path — just array indexing.

**content-hash build cache.** build layer caching is keyed by content hash, not by instruction order. reordering Dockerfile instructions doesn't invalidate the cache (unlike Docker).

**SQLite for everything.** container state, image metadata, service names, secrets, network policies, deployment history, and Raft log all live in SQLite. in cluster mode, the database is replicated via Raft. no etcd, no separate state store.

## security model

1. **process isolation:** each container runs in its own set of namespaces. capabilities are dropped to a minimal set. seccomp restricts available syscalls.

2. **filesystem isolation:** overlayfs with pivot_root. dangerous bind mount targets (`/etc`, `/root`, `/proc`, `/sys`) are blocked. symlinks in overlay paths are rejected.

3. **network isolation:** containers get private IPs on an internal bridge. outbound traffic is NATed. inbound traffic requires explicit port mapping.

4. **secrets:** encrypted at rest (XChaCha20-Poly1305). mounted as files or env vars — never stored in plain text.

5. **API auth:** bearer token authentication with constant-time comparison. tokens are generated on first server start.

6. **cluster transport:** HMAC-SHA256 authentication on all cluster messages (Raft RPCs, gossip protocol), derived from the join token. token comparison is constant-time and does not leak token length. WireGuard encryption for all cross-node communication with keys exchanged during the join handshake.
