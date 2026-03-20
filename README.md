# yoq

yoq is a single Linux binary for building, running, networking, and deploying containers without stitching together Docker, Compose, Kubernetes, Istio, Helm, and a pile of glue.

Most teams do not need a platform made of separate control planes, YAML layers, sidecars, and operators just to run a few services reliably. They need containers, service discovery, rollouts, secrets, TLS, metrics, and a sane deployment model that one engineer can actually understand end to end.

That is the point of yoq. It collapses the usual stack into one operational model, one CLI, one state store, and one binary you can ship to a Linux host. Instead of outsourcing core behavior to half a dozen daemons, it builds directly on Linux primitives like namespaces, cgroups v2, io_uring, eBPF, and WireGuard.

Linux kernel 6.1+ is required.

## who this is for

yoq is a strong fit for:

- small-to-medium teams that want production features without building a platform team first
- multi-service applications that outgrew Compose but do not need the ecosystem breadth of Kubernetes
- operators who prefer direct, inspectable systems over layered abstractions
- Linux environments where shipping one binary is operationally attractive

yoq takes a different approach from the standard stack. instead of composing separate tools for images, runtime, orchestration, ingress, mesh, secrets, and observability, it keeps everything integrated with a small surface area. the tradeoff is a narrower ecosystem — you get one coherent system instead of a platform you can extend in every direction.

Kubernetes has a vast ecosystem and years of production hardening. yoq doesn't try to replace that. if you already depend on the full Kubernetes ecosystem surface, deep CRD-driven workflows, or broad vendor tooling built specifically around Kubernetes APIs, yoq is probably not the right fit.

## what you get

### runtime

- isolated containers with PID, NET, MNT, UTS, IPC, USER, and CGROUP namespaces
- cgroups v2 resource limits, overlayfs root filesystems, seccomp filters, and capability dropping
- process supervision, log capture, restart handling, and `exec` into running containers

### build

- Dockerfile support for the major directives, including multi-stage builds and build args
- content-hash caching so unchanged build steps are not re-executed
- optional TOML build manifest format

### service orchestration

- declarative multi-service manifests
- dependency ordering, workers, cron jobs, and dev mode with hot restart
- health checks, readiness probes, rollout history, rollback, and automatic rollback on failed updates

### networking and discovery

- per-container IPs on a bridge network
- built-in DNS-based service discovery
- port mapping, outbound NAT, and eBPF-based load balancing and policy enforcement where available
- WireGuard-based cluster networking for multi-node deployments

### production features

- encrypted secrets store with rotation
- TLS termination with ACME provisioning and renewal
- service and pairwise network metrics
- policy controls between services
- status and resource reporting

### GPU & training

- GPU detection and passthrough into containers
- gang scheduling for distributed training workloads
- NCCL mesh configuration and InfiniBand/RDMA support
- MIG partitioning and MPS sharing
- training job orchestration with checkpoints, fault tolerance, and data sharding

### storage

- S3-compatible object storage gateway
- volume drivers: local, host, NFS, parallel filesystem

### clustering

- raft-based server nodes with SQLite-backed state replication
- SWIM gossip protocol for scalable failure detection
- role separation: server nodes (raft + API + scheduler) vs agent nodes (gossip + workloads)
- HMAC-SHA256 authenticated cluster transport
- agent registration, heartbeats, placement, drain, and cluster status
- rolling upgrades with leader step-down
- remote operations via `--server host:port`

### diagnostics

- `yoq doctor` pre-flight system checks (kernel, cgroups, eBPF, GPU, WireGuard, InfiniBand, disk)
- `yoq backup` / `yoq restore` for SQLite state

### alerting

- threshold-based alerts (CPU, memory, restart count, p99 latency, error rate) with webhook notifications

## quickstart

### requirements

- Linux kernel 6.1+ (sorry no Mac support)
- Zig 0.15.2

### build

```bash
make build
```

For GPU-focused validation without running the full suite, use `zig build test-gpu`. For a real-host smoke checklist, see [docs/gpu-validation.md](docs/gpu-validation.md).

### one-liner
```bash
curl -fsSL https://yoq.dev/install | bash
```

### run one container

```bash
yoq run alpine:latest echo "hello from yoq"
yoq ps
yoq logs <id-or-name>
```

### run a small app

```toml
[service.redis]
image = "redis:7"
ports = ["6379:6379"]

[service.web]
image = "nginx:latest"
ports = ["8080:80"]
depends_on = ["redis"]
```

```bash
yoq up -f manifest.toml
yoq status
yoq down -f manifest.toml
```

## command overview

### containers

```text
yoq run <image|rootfs> [command]     run a container
yoq ps [--json]                      list containers
yoq stop <id|name>                   stop a container
yoq rm <id|name>                     remove a stopped container
yoq logs <id|name> [--tail N]        show container output
yoq restart <id|name>                restart a container
yoq exec <id|name> <cmd> [args...]   run a command in a container
```

### images

```text
yoq pull <image>                     pull from a registry
yoq push <source> [target]           push to a registry
yoq images [--json]                  list local images
yoq inspect <image>                  show image metadata
yoq rmi <image>                      remove an image
yoq prune [--json]                   delete unreferenced blobs and layers
```

### build and manifests

```text
yoq build [-t tag] [-f Dockerfile] . build an image
                  [--format toml]   build from a TOML manifest
yoq up [-f manifest.toml]            start services from a manifest
yoq up [service...]                  start named services and dependencies
yoq up --dev                         watch and hot-restart on changes
yoq up --server host:port            deploy to a cluster
yoq down [-f manifest.toml]          stop services from a manifest
yoq run-worker <name>                run a one-shot worker
yoq init [-f path]                   scaffold a manifest
yoq validate [-f manifest.toml] [-q] validate a manifest
```

### deployment and operations

```text
yoq rollback <service>               roll back a deployment
yoq history <service>                show deployment history
yoq status [--verbose]               show service status and resources
yoq metrics [service]                show service metrics
yoq metrics --pairs                  show service-to-service metrics
yoq policy deny <src> <tgt>          block traffic between services
yoq policy allow <src> <tgt>         allow traffic between services
yoq policy rm <src> <tgt>            remove a policy rule
yoq policy list                      list policy rules
```

### secrets and certificates

```text
yoq secret set <name> <value>        store a secret
yoq secret get <name>                read a secret
yoq secret rm <name>                 delete a secret
yoq secret list                      list secrets
yoq secret rotate <name>             rotate a secret
yoq cert provision <domain>          provision a TLS certificate
yoq cert renew <domain>              renew a certificate
yoq cert install <domain> --cert <path> --key <path>
yoq cert list                        list certificates
yoq cert rm <domain>                 remove a certificate
```

### server and cluster

```text
yoq serve [--port PORT]              start the API server
yoq init-server [--id N] [--port P]  start a cluster server node
    [--api-port P] [--peers ...]
    [--token TOKEN]
yoq join <host> --token <token>      join as an agent node
yoq cluster status                   show cluster health
yoq nodes [--server host:port]       list agent nodes
yoq drain <id> [--server host:port]  drain an agent node
```

### GPU

```text
yoq gpu topo [--json]                show GPU topology
yoq gpu bench [--gpus N]             GPU-to-GPU bandwidth benchmark
    [--size BYTES] [--iterations N]
```

### training

```text
yoq train start <name>              start a training job
yoq train status <name>             show training job status
yoq train stop <name>               stop a training job
yoq train pause <name>              pause a training job
yoq train resume <name>             resume a paused job
yoq train scale <name>              scale training ranks
yoq train logs <name> [--rank N]    show logs for a training rank
```

### diagnostics

```text
yoq doctor [--json]                  check system readiness
yoq backup [--output path]           backup database state
yoq restore <path>                   restore database from backup
```

### meta

```text
yoq version [--json]                 print version
yoq help                             show help
yoq completion <bash|zsh|fish>       output shell completion
```

Notes:

- `--json` is available on `ps`, `images`, `prune`, `version`, `gpu topo`, and `doctor`.
- crons defined in the manifest start automatically with `yoq up`.
- deployment, metrics, and certificate commands also support `--server host:port`.

## current status

~77K lines of Zig, ~1474 tests, v0.1.1. coverage across runtime, images, networking, build, manifests, clustering, GPU, training, storage, secrets, TLS, metrics, and alerting.

see [docs/architecture.md](docs/architecture.md) for subsystem details and [docs/users-guide.md](docs/users-guide.md) for a guide to the internals.

## architecture snapshot

yoq is organized as a set of integrated subsystems:

- `runtime/` — container lifecycle, namespaces, cgroups, filesystem, security, logs, exec
- `image/` — OCI registry, blob storage, layer extraction, metadata
- `network/` — bridge networking, DNS, NAT, WireGuard, eBPF, policy
- `build/` and `manifest/` — image builds, manifests, orchestration, health, updates, training, alerting
- `cluster/`, `api/`, and `state/` — replication, scheduling, remote control, persistent state, backup/restore
- `gpu/` — detection, passthrough, health, scheduling, InfiniBand/NCCL mesh
- `storage/` — S3-compatible object storage, volume management
- `tls/` and `lib/` — certificates, proxying, utilities, CLI, logging, doctor

see [docs/architecture.md](docs/architecture.md) for the full breakdown.

## examples

The [`examples/`](examples/) directory has ready-to-use manifests:

- [`examples/redis/`](examples/redis/) for the simplest possible single-service setup
- [`examples/web-app/`](examples/web-app/) for a multi-service app with postgres, redis, workers, and health checks
- [`examples/cron/`](examples/cron/) for scheduled jobs with `every = "1h"`
- [`examples/cluster/`](examples/cluster/) for a minimal multi-node cluster flow

```bash
yoq up -f examples/redis/manifest.toml
```

## what's next

- L7 routing — HTTP-level routing and request-based load balancing (currently DNS-level only)
- hardening — continued stability, edge-case testing, and operational polish
- web UI remains intentionally deferred; the CLI is the primary interface
- image signing is not built in; use cosign externally
