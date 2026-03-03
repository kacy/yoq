# yoq

a single binary that replaces Docker + Kubernetes + Istio + Helm for 90% of teams.

## what

yoq combines container runtime, orchestration, networking, and service mesh into one static binary. built on modern Linux primitives (cgroups v2, eBPF, WireGuard, io_uring) instead of the 2013-era stack everything else is built on.

## status

phases 1-4 complete: container primitives, OCI images, networking, and build engine. phase 5 (manifest + dev mode) is underway.

containers run in isolated namespaces with cgroups v2 resource limits, overlayfs from OCI image layers, seccomp syscall filters, and dropped capabilities. images are pulled from any OCI registry (Docker Hub, GHCR, etc.), extracted, and cached locally with layer deduplication.

networking gives each container its own IP on a bridge network (10.42.0.0/16), with NAT for outbound traffic and port mapping for inbound. DNS service discovery lets containers find each other by name — a userspace resolver on the bridge gateway answers A record queries for registered service names and forwards everything else upstream.

the build engine parses Dockerfiles (FROM, RUN, COPY, ENV, EXPOSE, ENTRYPOINT, CMD, WORKDIR) and produces OCI images with content-hash caching. identical build steps are never re-executed, regardless of instruction order.

phase 5 work has started with manifest spec types (services, volumes, ports), a TOML manifest loader with validation and dependency ordering, and container exec support. the foundation for `yoq up` multi-service orchestration is in place.

what works on Linux (kernel 6.1+):
- `yoq run nginx:latest` — pulls, extracts, and runs a container
- `yoq run -p 8080:80 nginx:latest` — with host port mapping
- `yoq run -p 8080:80 -p 443:443 nginx:latest` — multiple port mappings
- `yoq run --no-net alpine /bin/sh` — run without networking
- `yoq run --name db postgres:latest` — assign a name for DNS service discovery
- `yoq run alpine:latest /bin/echo hello` — run with a custom command
- `yoq build .` — build an image from a Dockerfile
- `yoq build -t myapp:latest .` — build with a tag
- `yoq build -f custom.Dockerfile .` — build from a custom Dockerfile
- `yoq ps` — list containers with status and network info
- `yoq logs <id>` — view captured stdout/stderr with timestamps
- `yoq logs <id> --tail 20` — last 20 lines
- `yoq stop <id>` — send SIGTERM to a running container
- `yoq rm <id>` — remove a stopped container and clean up
- `yoq pull <image>` — pull and cache an image
- `yoq images` / `yoq rmi <image>` — manage local images
- `yoq exec <id> <cmd> [args...]` — run a command inside a running container

## requirements

- Linux kernel 6.1+ (user namespace support)
- Zig 0.15.2

## build

```
make build
```

## usage

```
yoq run <image> [command]           # pull and run a container
yoq run -p 8080:80 nginx:latest    # map host port to container port
yoq run --name db postgres:latest  # assign a name for DNS discovery
yoq run --no-net alpine /bin/sh    # run without networking
yoq run ./rootfs /bin/sh           # run from a local rootfs directory
yoq build .                        # build an image from a Dockerfile
yoq build -t myapp:latest .        # build with a tag
yoq build -f custom.Dockerfile .   # build from a custom Dockerfile
yoq ps                             # list containers
yoq logs <id>                      # view container output
yoq logs <id> --tail 20            # last 20 lines
yoq stop <id>                      # stop a running container
yoq rm <id>                        # remove a stopped container
yoq pull <image>                   # pull an image from a registry
yoq images                         # list pulled images
yoq rmi <image>                    # remove a pulled image
yoq exec <id> <cmd> [args...]      # run a command in a running container
```

## architecture

```
src/
  main.zig              CLI entry point, argument parsing
  runtime/
    container.zig        container lifecycle (create/start/stop/rm)
    namespaces.zig       clone3, user/pid/net/mnt namespace setup
    cgroups.zig          cgroups v2 (cpu, memory, pids limits)
    filesystem.zig       overlayfs, pivot_root, bind mounts
    security.zig         seccomp filters, capability dropping
    process.zig          process supervision, signal handling
    logs.zig             stdout/stderr capture to files
    exec.zig             execute commands in running containers
  image/
    registry.zig         OCI registry client (token auth, manifests, blobs)
    store.zig            content-addressable blob storage
    layer.zig            layer extraction and deduplication
    spec.zig             OCI image/manifest spec types
  network/
    setup.zig            network orchestrator (bridge + veth + NAT)
    bridge.zig           bridge and veth pair management via netlink
    netlink.zig          raw netlink socket interface
    ip.zig               IP allocation from sqlite pool
    nat.zig              iptables NAT, forwarding, port mapping
    dns.zig              userspace DNS resolver for service discovery
  build/
    dockerfile.zig       Dockerfile parser (FROM, RUN, COPY, ENV, etc.)
    engine.zig           build engine with content-hash caching
    context.zig          build context file hashing and copying
  state/
    store.zig            sqlite container/image metadata
    schema.zig           database schema and migrations
  lib/
    log.zig              structured logging
    paths.zig            XDG data directory helpers
    toml.zig             TOML parser for manifest files
    syscall.zig          low-level syscall wrappers
  manifest/
    spec.zig             manifest type definitions (services, volumes, ports)
    loader.zig           TOML manifest parser with dependency ordering
```

## what's next

- **phase 5: manifest + dev mode** — manifest spec types and loader done, next: orchestrator (`yoq up` / `yoq down`), dev mode with hot reload
- **phase 6: clustering** — Raft consensus, multi-node scheduling, WireGuard mesh networking
- **phase 7: production** — health checks, rolling updates, secrets, TLS, eBPF observability
