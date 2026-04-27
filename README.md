# yoq

yoq is a single Linux binary for building, running, networking, and deploying containers without stitching together Docker, Compose, Kubernetes, Istio, Helm, and a pile of glue.

Most teams do not need multiple control planes, YAML stacks, sidecars, and operators just to run a few services reliably. They need containers, service discovery, rollouts, secrets, TLS, metrics, and a deployment model that one engineer can actually understand from top to bottom.

yoq keeps that in one place: one CLI, one state store, and one binary you can ship to a Linux host. Under the hood it uses Linux primitives directly, including namespaces, cgroups v2, io_uring, eBPF, and WireGuard.

Linux kernel 6.1+ is required.

The recommended operator flow is app-first:

- `yoq up`
- `yoq apps`
- `yoq status --app [name]`
- `yoq history --app [name]`
- `yoq rollback --app [name]`
- `yoq rollout pause|resume|cancel --app [name]`

## who this is for

yoq makes sense for:

- small-to-medium teams that want production features without building a platform team first
- multi-service applications that outgrew Compose but do not need the ecosystem breadth of Kubernetes
- operators who prefer direct, inspectable systems over layered abstractions
- Linux environments where shipping one binary is easier to live with

yoq takes a different approach from the standard stack. instead of composing separate tools for images, runtime, orchestration, ingress, mesh, secrets, and observability, it keeps the core pieces together behind a smaller surface area. The tradeoff is straightforward: a narrower ecosystem in exchange for a system that is easier to reason about.

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
- health checks, readiness probes, app release history, rollback, rollout policies, and automatic rollback on failed updates

### networking and discovery

- per-container IPs on a bridge network
- built-in DNS-based service discovery
- port mapping, outbound NAT, and eBPF-based load balancing and policy enforcement where available
- WireGuard-based cluster networking for multi-node deployments
- HTTP routing for HTTP/1.1, plaintext HTTP/2 via prior-knowledge `h2c` or HTTP/1.1 `Upgrade: h2c`, and TLS-terminated HTTP/2 via ALPN when a routed host is also bound to `service.<name>.tls.domain`
- gRPC health checks using the standard `grpc.health.v1.Health/Check` RPC
- route-level rewrites, method/header matching, weighted backend selection, and best-effort request mirroring

current gRPC routing limits:

- direct listener traffic supports both prior-knowledge `h2c` and HTTP/1.1 `Upgrade: h2c`; TLS/ALPN HTTP/2 routing works through the TLS terminator when the routed host matches a service `tls.domain`

### production features

- encrypted secrets store with rotation
- TLS termination with ACME provisioning and renewal
- service and pairwise network metrics
- policy controls between services
- status and resource reporting

current ACME/TLS limits:

- DNS-01 requires explicit provider configuration and provider credentials in `yoq secret`
- HTTP-01 still requires port 80 on the target host during provision and renewal

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
- Zig 0.16.0

### build

```bash
make build
```

For the app/control-plane smoke lane, use `make test-operator` or `zig build test-operator`. It keeps the highest-signal local app lifecycle, rollback, rollout-control, and `/apps/*` route-flow regressions together without pulling in the full unit suite.

For the network/service-rollout smoke lane, use `make test-network` or `zig build test-network`. It keeps deterministic status/metrics, service-registry bridge, rollout-flag, and reconciler coverage together without depending on privileged proxy/runtime tests.

For GPU-focused validation without running the full suite, use `zig build test-gpu`. For a real-host smoke checklist, see [docs/gpu-validation.md](docs/gpu-validation.md).
For a temporary 5-node GCP validation rig that exercises cluster networking and GPU hosts, see [docs/gcp-cluster-validation.md](docs/gcp-cluster-validation.md).
For an end-to-end operator evaluation flow across local runtime, HTTP routing, and clustered deployment, see [docs/golden-path.md](docs/golden-path.md).
For cluster bootstrap, day-2 operations, and failure drills, see [docs/cluster-guide.md](docs/cluster-guide.md).
For rollout strategies, rollout state, control state, checkpoints, and recovery, see [docs/rollouts.md](docs/rollouts.md).

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

### run an app-first mixed workload

```toml
[service.api]
image = "ghcr.io/example/api:latest"
ports = ["8080:8080"]
depends_on = ["redis"]

[service.api.health_check]
type = "http"
path = "/health"
port = 8080

[service.api.rollout]
strategy = "canary"
parallelism = 2
delay_between_batches = "5s"
failure_action = "rollback"
health_check_timeout = "20s"

[service.redis]
image = "redis:7"
ports = ["6379:6379"]

[worker.migrate]
image = "ghcr.io/example/api:latest"
command = ["./bin/migrate"]
depends_on = ["redis"]

[cron.cleanup]
image = "ghcr.io/example/api:latest"
command = ["./bin/cleanup"]
every = "1h"

[training.finetune]
image = "ghcr.io/example/trainer:latest"
command = ["python", "train.py"]
gpus = 4
```

```bash
yoq up -f manifest.toml
yoq apps
yoq status --app
yoq history --app
yoq rollout pause --app
yoq rollout resume --app
yoq rollback --app
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
yoq up --skip-preflight              bypass local manifest readiness checks
yoq up --server host:port            deploy to a cluster
yoq down [-f manifest.toml]          stop services from a manifest
yoq run-worker <name>                run a one-shot worker
yoq run-worker --server host:port <name>
yoq init [-f path]                   scaffold a manifest
yoq validate [-f manifest.toml] [-q] validate a manifest
```

### deployment and operations

```text
yoq rollback <service>               roll back a service deployment
yoq rollback --app [name]            re-apply the previous successful app release
yoq rollback --app [name] [--release <id>] [--print]
yoq rollback --app [name] --server host:port [--release <id>] [--print]
yoq history <service>                show service deployment history
yoq history --app [name]             show local app release history
yoq history --app [name] --server host:port [--json]
                                     show remote app release history
yoq status [--verbose]               show service status and resources
yoq status --app [name]              show local app release status
yoq status --app [name] --server host:port
                                     show remote app release status
yoq apps [--json] [--status s|--failed|--in-progress]
                                     list local app release summaries
yoq apps --server host:port [--json] [--status s|--failed|--in-progress]
                                     list remote app release summaries
yoq rollout pause --app [name]       pause an active app rollout
yoq rollout resume --app [name]      resume an active or stored app rollout
yoq rollout cancel --app [name]      cancel an active app rollout
yoq rollout <...> --server host:port control remote app rollouts
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
yoq cert provision <domain> [--email <email>] [--staging] [--dns-provider <provider>]
                                     provision a TLS certificate via ACME
yoq cert renew <domain> [--email <email>] [--staging] [--dns-provider <provider>]
                                     renew a TLS certificate via ACME
yoq cert install <domain> --cert <path> --key <path>
yoq cert list [--json]               list certificates
yoq cert rm <domain>                 remove a certificate
```

If `--email` is omitted for the standalone ACME flow, yoq uses `YOQ_ACME_EMAIL` when set and otherwise falls back to `admin@<domain>`.
DNS-01 supports built-in `cloudflare`, `route53`, and `gcloud` providers plus an `exec` fallback. Provider credentials are referenced through `yoq secret` entries rather than embedded directly in manifests.
before yoq opens an ACME order, it checks the local challenge config and referenced DNS secrets. `yoq cert list --json` shows renewal metadata for managed certificates: challenge type, provider, directory URL, and DNS polling settings.

For app rollbacks, omitting `--release` picks the previous successful release before the current one. Use `--print` to inspect the selected stored app snapshot without applying it.
For app rollouts, status and history expose a nested `rollout` view with rollout state, control state, target counts, failure details, and checkpoint data. The older top-level fields are still there for compatibility.

### server and cluster

```text
yoq serve [--port PORT] [--http-proxy-bind ADDR] [--http-proxy-port PORT]
                                     start the API server
yoq init-server [--id N] [--port P]  start a cluster server node
    [--api-port P] [--peers ...]
    [--token TOKEN] [--http-proxy-bind ADDR]
    [--http-proxy-port PORT]
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
yoq train start [--server host:port] <name>              start a training job
yoq train status [--server host:port] <name>             show training job status
yoq train stop [--server host:port] <name>               stop a training job
yoq train pause [--server host:port] <name>              pause a training job
yoq train resume [--server host:port] <name>             resume a paused job
yoq train scale [--server host:port] <name> --gpus <n>   scale training ranks
yoq train logs [--server host:port] <name> [--rank N]    show logs for a training rank
```

For clustered training logs, the control plane proxies log reads to the agent that hosts the selected rank. If that agent is unreachable or does not expose the log endpoint, the API returns an explicit hosting-agent error instead of an empty result.

### diagnostics

```text
yoq doctor [-f manifest.toml] [--json]
                                     check system and manifest readiness
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

- `--json` is available on `ps`, `images`, `prune`, `version`, `gpu topo`, and `doctor`. `yoq doctor -f manifest.toml --json` groups system and manifest checks separately.
- local `yoq up` runs manifest readiness checks before starting services; use `--skip-preflight` only when you need to bypass a known local preflight failure.
- crons defined in the manifest start automatically with `yoq up`.
- deployment, metrics, and certificate commands also support `--server host:port`.
- clustered manifest deploys now go through the app-first `/apps/apply` API and carry services, workers, crons, and training definitions in one app snapshot. the older `/deploy` route is still there for legacy callers.
- remote app applies now register active cron schedules in cluster state, and `yoq apps` / `yoq status --app` include live training runtime summaries for the current app.

## current status

~122K lines of Zig, ~2191 tests, v0.2.0. Coverage spans runtime, images, networking, build, manifests, clustering, GPU, training, storage, secrets, TLS, metrics, and alerting.

for a compact release summary, see [docs/releases/0.2.0.md](docs/releases/0.2.0.md).

see [docs/architecture.md](docs/architecture.md) for subsystem details and [docs/users-guide.md](docs/users-guide.md) for a guide to the internals.

## architecture snapshot

yoq is organized as a set of subsystems that fit together pretty tightly:

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
- [`examples/http-routing/`](examples/http-routing/) for host-, path-, method-, and header-based HTTP routing
- [`examples/cluster/`](examples/cluster/) for a minimal multi-node cluster flow
- [docs/golden-path.md](docs/golden-path.md) for the recommended end-to-end evaluation workflow

```bash
yoq up -f examples/redis/manifest.toml
```

## what's next

- hardening — continued stability, edge-case testing, and operational polish toward v1.0
- web UI remains intentionally deferred; the CLI is the primary interface
- image signing is not built in; use cosign externally
