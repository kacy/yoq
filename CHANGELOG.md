# changelog

all notable changes to yoq are documented in this file.

format is based on [keep a changelog](https://keepachangelog.com/).

## unreleased

### added

- **gossip:** SWIM failure detection protocol for scalable membership and health monitoring
- **cluster auth:** HMAC-SHA256 authentication on all cluster messages (raft and gossip), derived from join token
- **agent API:** role and region fields in agent API JSON responses
- **transport:** connection pooling in cluster transport for TCP connection reuse

### fixed

- **security:** token comparison timing side-channel — constant-time comparison regardless of token length
- **state machine:** SQL statement redacted from state machine error logs
- **network hardening:** message size limits and connection validation in registry and cluster transport
- **robustness:** cgroup resource limit verification and safe integer casts for edge cases

### added

- **container runtime:** full namespace isolation (PID, NET, MNT, UTS, IPC, USER, CGROUP), cgroups v2 resource limits, overlayfs, seccomp filters, rootless containers
- **OCI images:** pull/push to any OCI registry, content-addressable blob store, layer deduplication, image inspect and prune
- **networking:** bridge + veth networking, eBPF DNS interception, load balancing, per-service metrics, network policy enforcement, WireGuard mesh
- **build engine:** Dockerfile parser (all major directives), content-hash caching, multi-stage builds, TOML declarative build format
- **manifest:** TOML manifest for multi-service apps, dependency ordering, health checks, readiness probes, rolling updates with automatic rollback
- **workers:** one-shot tasks (e.g., database migrations) via `run-worker`
- **crons:** scheduled recurring tasks with `every` interval syntax
- **selective startup:** `yoq up <service>` starts individual services with their dependencies
- **dev mode:** inotify file watching, hot restart, colored log multiplexing
- **clustering:** raft consensus, SQLite state replication, bin-packing scheduler, agent join/drain, cross-node service discovery
- **secrets:** encrypted storage, rotation, mounted as files or env vars
- **TLS:** ACME auto-provisioning, TLS 1.3 handshake, SNI routing, auto-renewal
- **observability:** eBPF per-service and per-pair metrics, PSI resource monitoring
- **network policies:** eBPF-based allow/deny between services

### fixed

- **raft transport:** fixed authentication to work with TCP ephemeral ports (previously rejected valid messages due to port mismatch between ephemeral source port and peer's listening port)
- **cluster node initialization:** fixed shared_key timing bug where authentication was checked before the key was set
- **cluster node cleanup:** fixed double-free bug where raft peers were freed twice (once in raft.deinit, once in node.deinit)
- **cluster test harness:** fixed simultaneous startup with proper full peer list configuration
