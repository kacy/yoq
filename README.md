# yoq

a single binary that replaces Docker + Kubernetes + Istio + Helm for 90% of teams.

## what

yoq combines container runtime, orchestration, networking, and service mesh into one static binary. built on modern Linux primitives (cgroups v2, eBPF, WireGuard, io_uring) instead of the 2013-era stack everything else is built on.

## status

early development. phase 1: container primitives.

## requirements

- Linux kernel 6.1+
- Zig 0.15.2

## build

```
make build
```

## usage

```
yoq run <image> <command>    # run a container
yoq ps                       # list containers
yoq logs <id>                # view container logs
yoq stop <id>                # stop a container
```
