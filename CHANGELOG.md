# changelog

all notable changes to yoq are documented in this file.

format is based on [keep a changelog](https://keepachangelog.com/).

## unreleased

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
