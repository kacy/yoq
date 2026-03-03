# yoq

a single binary that replaces Docker + Kubernetes + Istio + Helm for 90% of teams.

## what

yoq combines container runtime, orchestration, networking, and service mesh into one static binary. built on modern Linux primitives (cgroups v2, eBPF, WireGuard, io_uring) instead of the 2013-era stack everything else is built on.

## status

phases 1-2 complete: container primitives and OCI images.

containers run in isolated namespaces with cgroups v2 resource limits, overlayfs from OCI image layers, seccomp filters, and dropped capabilities. images are pulled from any OCI registry (Docker Hub, GHCR, etc.), extracted, and cached locally.

what works on Linux (kernel 6.1+):
- `yoq run nginx:latest` — pulls, extracts, and runs a container
- `yoq run alpine:latest /bin/echo hello` — run with a custom command
- `yoq ps` — list containers with status
- `yoq logs <id>` — view captured stdout/stderr with timestamps
- `yoq stop <id>` — send SIGTERM to a running container
- `yoq rm <id>` — remove a stopped container and clean up
- `yoq pull <image>` — pull and cache an image
- `yoq images` / `yoq rmi <image>` — manage local images

## requirements

- Linux kernel 6.1+ (user namespace support)
- Zig 0.15.2

## build

```
make build
```

## usage

```
yoq run <image> [command]    # pull and run a container
yoq run ./rootfs /bin/sh     # run from a local rootfs directory
yoq ps                       # list containers
yoq logs <id>                # view container output
yoq logs <id> --tail 20      # last 20 lines
yoq stop <id>                # stop a running container
yoq rm <id>                  # remove a stopped container
yoq pull <image>             # pull an image from a registry
yoq images                   # list pulled images
yoq rmi <image>              # remove a pulled image
```
