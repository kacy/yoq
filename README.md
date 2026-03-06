# yoq

yoq is a single Linux binary for building, running, networking, and deploying containers without stitching together Docker, Compose, Kubernetes, Istio, Helm, and a pile of glue.

Most teams do not need a platform made of separate control planes, YAML layers, sidecars, and operators just to run a few services reliably. They need containers, service discovery, rollouts, secrets, TLS, metrics, and a sane deployment model that one engineer can actually understand end to end.

That is the point of yoq. It collapses the usual stack into one operational model, one CLI, one state store, and one binary you can ship to a Linux host. Instead of outsourcing core behavior to half a dozen daemons, it builds directly on Linux primitives like namespaces, cgroups v2, io_uring, eBPF, and WireGuard.

Linux kernel 6.1+ is required.

## why this exists

The standard container stack grew by accretion:

- one tool to build images
- one tool to run containers
- one file format for local development
- another system for production scheduling
- extra layers for ingress, service discovery, mesh, secrets, TLS, and observability

That stack can be the right answer for very large organizations. For most teams, it creates more moving parts than the application actually needs. The operational burden becomes the platform.

yoq takes the opposite approach: keep the system integrated, keep the surface area small, and ship the production features people usually bolt on later.

## why yoq is better for most teams

- Fewer moving parts: one binary instead of a runtime, orchestrator, ingress layer, mesh, and templating stack.
- One mental model: local containers, multi-service apps, and clustered deployments all use the same CLI and same resource model.
- Less operational glue: service discovery, TLS, rollouts, secrets, metrics, and network policy are built in.
- Less translation work: you do not need to move from Dockerfiles to Compose to Helm charts to controller-specific CRDs just to keep shipping.
- Easier debugging: there is one codebase, one state store, and one place to reason about failures.

This is not a claim that yoq is the right answer for every environment. It is a claim that the usual stack is often overbuilt for what small and mid-sized teams actually need.

## why not the usual stack

For many teams, the default path looks like this:

- Docker for images and local containers
- Compose for local multi-service development
- Kubernetes for scheduling
- Helm for packaging
- ingress controllers and cert tooling for edge traffic
- service mesh or extra controllers for traffic policy and observability

yoq keeps those responsibilities in one system:

- OCI image build and registry operations
- container runtime and process supervision
- service orchestration from a manifest
- built-in service discovery and networking
- TLS, secrets, health checks, rollouts, and metrics
- optional multi-node clustering

The result is a smaller stack to install, upgrade, debug, and teach.

## best fit

yoq is a strong fit for:

- small-to-medium teams that want production features without building a platform team first
- multi-service applications that outgrew Compose but do not need the ecosystem breadth of Kubernetes
- operators who prefer direct, inspectable systems over layered abstractions
- Linux environments where shipping one binary is operationally attractive

yoq is probably not the right fit if you already depend on the full Kubernetes ecosystem surface, deep CRD-driven workflows, or broad vendor tooling built specifically around Kubernetes APIs.

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

### clustering

- raft-based server nodes with SQLite-backed state replication
- agent registration, heartbeats, placement, drain, and cluster status
- remote operations via `--server host:port`

## quickstart

### requirements

- Linux kernel 6.1+ (sorry no Mac support)
- Zig 0.15.2

### build

```bash
make build
```

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

### meta

```text
yoq version [--json]                 print version
yoq help                             show help
yoq completion <bash|zsh|fish>       output shell completion
```

Notes:

- `--json` is currently available on `ps`, `images`, `prune`, and `version`.
- crons defined in the manifest start automatically with `yoq up`.
- deployment, metrics, and certificate commands also support `--server host:port`.

## current status

yoq is substantially implemented today: roughly 51k lines of Zig, around 1019 tests, and coverage across runtime, images, networking, build, manifests, clustering, secrets, TLS, and metrics.

Implemented areas include:

- container runtime with namespaces, cgroups v2, overlayfs, seccomp, supervision, logs, and exec
- OCI image pull, push, inspect, extraction, caching, and pruning
- networking with bridge setup, DNS discovery, port mapping, eBPF hooks, and WireGuard mesh support
- build engine with Dockerfile parsing, multi-stage builds, caching, and TOML manifests
- manifest-driven service orchestration, health checks, workers, cron scheduling, dev mode, rollouts, and rollback
- raft-backed clustering with agent management and scheduling
- secrets, TLS termination, ACME, network policy, and observability features

## architecture snapshot

yoq is organized as a small set of integrated subsystems:

- `runtime/` handles container lifecycle, namespaces, cgroups, filesystem setup, security, logs, and exec
- `image/` handles OCI registry interactions, blob storage, layer extraction, and image metadata
- `network/` handles bridge networking, DNS, NAT, WireGuard, eBPF integration, and policy enforcement
- `build/` and `manifest/` handle image builds, application manifests, orchestration, health, updates, and dev workflows
- `cluster/`, `api/`, and `state/` handle replication, scheduling, remote control, and persistent state
- `tls/` and `lib/` provide certificate management, proxying, shared utilities, CLI helpers, and logging

The design goal is straightforward: keep the control plane close to the runtime, avoid unnecessary layers, and rely on Linux kernel primitives directly when they provide a simpler and more coherent implementation.

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

- web UI remains intentionally deferred; the CLI is the primary interface
- GPU scheduling
- multi-region federation
- advanced L7 routing
- plugin system
- image signing is not built in today; use cosign externally
