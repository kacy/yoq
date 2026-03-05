# yoq

a single binary that replaces Docker + Kubernetes + Istio + Helm for 90% of teams.

## what

yoq combines container runtime, orchestration, networking, and service mesh into one static binary. built on modern Linux primitives (cgroups v2, io_uring, eBPF) instead of the 2013-era stack everything else is built on. networking uses eBPF programs for DNS interception, load balancing, per-service metrics, and network policy enforcement, with iptables NAT as the outbound path. WireGuard mesh handles cross-node encryption.

## status

**~85% complete.** ~43k lines of Zig, ~920 tests. phases 1-6 are substantially complete. phase 7 production features are roughly half done.

**container runtime (phase 1) — ~98%:** containers run in isolated namespaces (PID, NET, MNT, UTS, IPC, USER, CGROUP) with cgroups v2 resource limits, overlayfs from OCI image layers, seccomp syscall filters, and dropped capabilities. process supervision, log capture, and exec into running containers all work. rootless containers via user namespace uid/gid mappings are implemented.

**OCI images (phase 2) — ~95%:** images are pulled from and pushed to any OCI registry (Docker Hub, GHCR, etc.) with token auth, extracted, and cached locally with layer deduplication. content-addressable blob store.

**networking (phase 3) — ~85%:** each container gets its own IP on a bridge network (10.42.0.0/16), with iptables NAT for outbound traffic and port mapping for inbound. eBPF programs handle DNS interception for service discovery, round-robin load balancing across replicas, per-IP and per-service-pair metrics collection, and network policy enforcement (allow/deny between services). WireGuard mesh for cross-node networking with automatic key exchange on node join. gap: XDP port mapping program not implemented.

**build engine (phase 4) — ~90%:** Dockerfile parser supports all major directives (FROM, RUN, COPY, ADD, ENV, EXPOSE, ENTRYPOINT, CMD, WORKDIR, ARG, VOLUME, SHELL, HEALTHCHECK, STOPSIGNAL, ONBUILD) and produces OCI images with content-hash caching. identical build steps are never re-executed, regardless of instruction order. `--build-arg` substitution and multi-stage builds (`COPY --from`) are supported. gap: TOML-based declarative build manifest not implemented.

**manifest + dev mode (phase 5) — ~80%:** TOML manifest format defines multi-service applications with dependency ordering, health checks, readiness probes, rolling update strategies, and secret references. `yoq up` starts all services, `yoq down` stops them in reverse order. dev mode (`--dev`) watches source directories with inotify and hot-restarts containers on file changes. colored log multiplexing prefixes output with service names. rolling updates with automatic rollback on health check failure. gaps: workers and crons not implemented in manifest spec, `up <service>` (start individual service) not implemented.

**clustering (phase 6) — ~95%:** raft consensus with TCP transport replicates state across server nodes using SQLite as the state machine. raft snapshots keep the log bounded and bring lagging followers up to date via InstallSnapshot RPC. agents join with tokens, report capacity via heartbeats every 5 seconds, and get work assigned by a bin-packing scheduler. WireGuard mesh with automatic key exchange on join encrypts cross-node traffic. cross-node service discovery works via cluster DNS. the API server exposes endpoints for cluster management. CLI commands cover the full lifecycle: `init-server`, `join`, `nodes`, `drain`, `cluster status`.

**production features (phase 7) — ~55%:** health checks (HTTP, TCP, exec) with configurable intervals and readiness probes. rolling updates with automatic rollback on failure. encrypted secrets store with rotation (mounted as files or env vars). TLS termination with ACME auto-provisioning, TLS 1.3 handshake, bidirectional proxy with SNI routing, and auto-renewal on startup. certificate management CLI. eBPF observability with per-IP and per-service-pair metrics. eBPF network policies (allow/deny between services). PSI metrics reading from cgroups v2. remaining: PSI-based auto-tuning suggestions.

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
yoq push <source> [target]           push an image to a registry
yoq images                           list pulled images
yoq rmi <image>                      remove a pulled image

# build
yoq build [-t tag] [-f Dockerfile] . build an image from a Dockerfile

# manifest
yoq up [-f manifest.toml]            start services from manifest
yoq up --dev                         dev mode: watch + hot restart
yoq up --server host:port            deploy to cluster
yoq down [-f manifest.toml]          stop all services

# deployment
yoq rollback <service>               rollback to previous version
yoq history <service>                show deployment history

# secrets
yoq secret set <name> <value>        store an encrypted secret
yoq secret get <name>                retrieve a secret
yoq secret rm <name>                 delete a secret
yoq secret list                      list all secrets
yoq secret rotate <name>             rotate a secret

# metrics
yoq metrics [service]                show per-service network stats
yoq metrics --pairs                  show service-to-service metrics

# certificates
yoq cert provision <domain>          provision TLS certificate via ACME
yoq cert renew <domain>              renew an existing certificate
yoq cert install <domain> --cert-file <path> --key-file <path>
yoq cert list                        list managed certificates
yoq cert rm <domain>                 remove a certificate

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

deployment, metrics, and certificate commands accept `--server host:port` for remote cluster operation.

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
    monitor.zig            resource monitoring
  image/
    registry.zig           OCI registry client (token auth, manifests, blobs, push)
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
    wireguard.zig          WireGuard mesh setup and key exchange
    ebpf.zig               eBPF program loading, map management
    policy.zig             eBPF-based network policy enforcement
    bpf/
      dns_intercept.zig    eBPF: DNS service discovery
      lb.zig               eBPF: round-robin load balancing
      metrics.zig          eBPF: per-IP and per-pair packet counting
      policy.zig           eBPF: network policy enforcement
  build/
    dockerfile.zig         Dockerfile parser (FROM, RUN, COPY, ENV, etc.)
    engine.zig             build engine with content-hash caching
    context.zig            build context file hashing and copying
  manifest/
    spec.zig               manifest type definitions (services, volumes, ports)
    loader.zig             TOML manifest parser with dependency ordering
    orchestrator.zig       service lifecycle and dependency management
    health.zig             health checks and readiness probes
    update.zig             rolling updates and rollback
  dev/
    watcher.zig            inotify file watcher for dev mode
    log_mux.zig            colored log multiplexing by service name
  tls/
    proxy.zig              TLS reverse proxy with SNI routing
    sni.zig                TLS ClientHello SNI extraction
    handshake.zig          TLS 1.3 handshake message construction
    record.zig             TLS record encryption/decryption (AES-256-GCM)
    pem.zig                PEM/DER parsing for keys and certificates
    csr.zig                certificate signing request generation
    jws.zig                JSON Web Signature for ACME protocol
    acme.zig               ACME client (Let's Encrypt)
    cert_store.zig         certificate storage and management
    backend.zig            backend registry for domain routing
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
    secrets.zig            encrypted secret storage
  lib/
    log.zig                structured logging
    paths.zig              XDG data directory helpers
    toml.zig               TOML parser for manifest files
    cli.zig                CLI output helpers
    json_helpers.zig       JSON encoding utilities
    exec_helpers.zig       process exec helpers
    syscall.zig            low-level syscall wrappers
    sql.zig                SQL escaping for raft proposals
    cmd.zig                shared command execution
```

## what's next

### high priority (unblocks production use)

- PSI-based auto-tuning suggestions from resource monitoring

### medium priority (completes phase promises)

- TOML declarative build manifest
- workers and crons in manifest spec

### lower priority (polish)

- XDP port mapping program
- `up <service>` (start individual service from manifest)
