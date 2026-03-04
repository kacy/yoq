# yoq

a single binary that replaces Docker + Kubernetes + Istio + Helm for 90% of teams.

## what

yoq combines container runtime, orchestration, networking, and service mesh into one static binary. built on modern Linux primitives (cgroups v2, io_uring) instead of the 2013-era stack everything else is built on. networking currently uses iptables and a userspace DNS resolver; eBPF programs for DNS interception, load balancing, and observability are planned but not yet implemented.

## status

~21k lines of Zig, ~460 tests. phases 1-6 are substantially implemented with some gaps noted below.

**container runtime (phase 1) — ~95%:** containers run in isolated namespaces (PID, NET, MNT, UTS, IPC, USER, CGROUP) with cgroups v2 resource limits, overlayfs from OCI image layers, seccomp syscall filters, and dropped capabilities. process supervision, log capture, and exec into running containers all work. gap: rootless containers via user namespaces (currently requires root).

**OCI images (phase 2) — ~90%:** images are pulled from any OCI registry (Docker Hub, GHCR, etc.) with token auth, extracted, and cached locally with layer deduplication. content-addressable blob store. gap: image push is not implemented (pull only).

**networking (phase 3) — ~70%:** each container gets its own IP on a bridge network (10.42.0.0/16), with iptables NAT for outbound traffic and port mapping for inbound. a userspace DNS resolver on the bridge gateway handles service discovery — containers find each other by name. gap: no eBPF programs (dns interception, load balancing, port mapping, metrics, network policy are all planned but not implemented). no load balancing across replicas.

**build engine (phase 4) — ~75%:** Dockerfile parser (FROM, RUN, COPY, ENV, EXPOSE, ENTRYPOINT, CMD, WORKDIR) produces OCI images with content-hash caching. identical build steps are never re-executed, regardless of instruction order. gap: TOML-based declarative build manifest not implemented.

**manifest + dev mode (phase 5) — ~80%:** TOML manifest format defines multi-service applications with dependency ordering. `yoq up` starts all services, `yoq down` stops them in reverse order. dev mode (`--dev`) watches source directories with inotify and hot-restarts containers on file changes. colored log multiplexing prefixes output with service names. gaps: workers and crons not implemented in manifest spec, secret references not supported, `up <service>` (start individual service) not implemented.

**clustering (phase 6) — ~70%:** raft consensus with TCP transport replicates state across server nodes using SQLite as the state machine. agents join with tokens, report capacity via heartbeats every 5 seconds, and get work assigned by a bin-packing scheduler. the API server exposes 15 endpoints for cluster management. CLI commands cover the full lifecycle: `init-server`, `join`, `nodes`, `drain`, `cluster status`. gaps: raft snapshots not implemented (log grows unbounded), WireGuard mesh for cross-node networking not started, cross-node service discovery doesn't work.

**production features (phase 7) — ~10%:** basic input validation at the API boundary. everything else is unimplemented: health checks, readiness probes, rolling updates, secrets store, TLS/ACME, eBPF observability, network policies.

## what works

Linux kernel 6.1+ required. commands grouped by function:

```
# containers
yoq run <image|rootfs> [command]     pull and run a container
yoq ps                               list containers
yoq stop <id>                        stop a running container
yoq rm <id>                          remove a stopped container
yoq logs <id> [--tail N]             view container output
yoq exec <id> <cmd> [args...]        run a command in a running container

# images
yoq pull <image>                     pull an image from a registry
yoq images                           list pulled images
yoq rmi <image>                      remove a pulled image

# build
yoq build [-t tag] [-f Dockerfile] . build an image from a Dockerfile

# manifest
yoq up [-f manifest.toml]            start services from manifest
yoq up --dev                         dev mode: watch + hot restart
yoq up --server host:port            deploy to cluster
yoq down [-f manifest.toml]          stop all services

# server
yoq serve [--port PORT]              start the API server

# cluster
yoq init-server [--id N] [--port P]  start a cluster server node
    [--api-port P] [--peers ...]
    [--token TOKEN]
yoq join <host> --token <token>      join cluster as agent node
yoq cluster status                   show cluster node status
yoq nodes [--server host:port]       list cluster agent nodes
yoq drain <id> [--server host:port]  drain an agent node

# meta
yoq version                          print version
yoq help                             show help
```

## requirements

- Linux kernel 6.1+ (user namespace support)
- Zig 0.15.2

## build

```
make build
```

## architecture

```
src/
  main.zig                CLI entry point, argument parsing
  runtime/
    container.zig          container lifecycle (create/start/stop/rm)
    namespaces.zig         clone3, user/pid/net/mnt namespace setup
    cgroups.zig            cgroups v2 (cpu, memory, pids limits)
    filesystem.zig         overlayfs, pivot_root, bind mounts
    security.zig           seccomp filters, capability dropping
    process.zig            process supervision, signal handling
    logs.zig               stdout/stderr capture to files
    exec.zig               execute commands in running containers
  image/
    registry.zig           OCI registry client (token auth, manifests, blobs)
    store.zig              content-addressable blob storage
    layer.zig              layer extraction and deduplication
    spec.zig               OCI image/manifest spec types
    oci.zig                OCI image config resolution
  network/
    setup.zig              network orchestrator (bridge + veth + NAT)
    bridge.zig             bridge and veth pair management via netlink
    netlink.zig            raw netlink socket interface
    ip.zig                 IP allocation from sqlite pool
    nat.zig                iptables NAT, forwarding, port mapping
    dns.zig                userspace DNS resolver for service discovery
  build/
    dockerfile.zig         Dockerfile parser (FROM, RUN, COPY, ENV, etc.)
    engine.zig             build engine with content-hash caching
    context.zig            build context file hashing and copying
  manifest/
    spec.zig               manifest type definitions (services, volumes, ports)
    loader.zig             TOML manifest parser with dependency ordering
    orchestrator.zig       service lifecycle and dependency management
  dev/
    watcher.zig            inotify file watcher for dev mode
    log_mux.zig            colored log multiplexing by service name
  cluster/
    raft.zig               raft consensus (leader election, log replication)
    raft_types.zig         raft protocol types and constants
    log.zig                persistent raft log (SQLite-backed)
    transport.zig          TCP transport for node-to-node communication
    state_machine.zig      applies committed entries to replicated SQLite DB
    node.zig               server node management (raft + state machine)
    config.zig             cluster configuration and peer parsing
    registry.zig           server-side agent registry
    agent_types.zig        shared agent/assignment types
    agent.zig              worker node agent (heartbeat, resource reporting)
    http_client.zig        HTTP client for agent-server communication
    scheduler.zig          bin-packing container placement
  api/
    http.zig               HTTP request/response parsing
    routes.zig             API route dispatch and handlers
    server.zig             HTTP server (io_uring + blocking fallback)
  state/
    store.zig              sqlite container/image metadata
    schema.zig             database schema and migrations
  lib/
    log.zig                structured logging
    paths.zig              XDG data directory helpers
    toml.zig               TOML parser for manifest files
    cli.zig                CLI output helpers
    json_helpers.zig       JSON encoding utilities
    exec_helpers.zig       process exec helpers
    syscall.zig            low-level syscall wrappers
    sql.zig                SQL escaping for raft proposals
```

## what's next

### high priority (unblocks production use)

- health checks and readiness probes (HTTP, TCP, exec)
- rolling updates with automatic rollback
- secrets store (encrypted at rest, mounted as files or env vars)
- raft snapshots (log grows unbounded without them)

### medium priority (completes phase promises)

- WireGuard mesh for cross-node networking
- eBPF networking (DNS interception, load balancing, port mapping)
- TOML declarative build manifest
- workers and crons in manifest spec

### lower priority (polish)

- rootless containers via user namespaces
- image push to registries
- TLS termination with ACME
- eBPF observability (request count, latency, error rate)
- network policies (eBPF-based allow/deny)
- PSI-based resource monitoring with auto-tuning
