# development

build with zig 0.16.0 on linux:

```bash
make build
```

run one test suite at a time. choose the suite that covers the change:

| command | coverage |
| --- | --- |
| `make test` | unit tests |
| `make test-operator` | app lifecycle, rollback, rollout control, and app api routes |
| `make test-network` | status, metrics, service registration, and rollout reconciliation |
| `make test-perf-smoke` | timing limits for manifest loading, route planning, and status serialization |
| `make test-golden-path` | cli startup, example manifests, and guide assumptions |
| `make test-gpu` | gpu logic without requiring a gpu host |
| `make test-hardening` | integration, contract, simulation, gpu, and parser regression tests |

`make test-hardening` covers runtime and parser changes that need more than the focused suites. it runs without root. see the [gpu validation guide](gpu-validation.md) for checks on real hardware.

## privileged runtime tests

these commands build the binary and use sudo for tests that need namespaces, cgroups, and host networking:

| command | coverage |
| --- | --- |
| `make test-runtime-core` | container lifecycle, errors, and resource limits |
| `make test-runtime-network` | bridge networking, port mapping, nat, and service discovery |
| `make test-runtime-cluster` | clusters, failure scenarios, stress, and api security |
| `make test-privileged` | all privileged runtime suites |

for direct zig invocations, put build options before the step name:

```bash
sudo zig build -Doptimize=ReleaseSafe -Drun-privileged-tests=true test-runtime-core
```

see the [operator evaluation guide](golden-path.md) for manual application checks and the [gcp validation guide](gcp-cluster-validation.md) for a temporary cluster with gpu hosts.

the `runtime-validation` workflow runs every lane on its schedule. manual runs can select `cluster` or `bpf` for a focused rerun; `all` includes the core and network lanes. normal pull request ci also checks the installer contract and runs real backup, verification, corruption-rejection, and restore commands against disposable state.

ci also runs `agent-recovery` with three real server processes and one joined agent in isolated network namespaces. it checks leader death, follower redirects, persisted terminal results, offline agent restart, and recovery of a complete fixed-voter backup set into fresh data roots. run it locally after building:

```bash
sudo env YOQ_BIN="$PWD/zig-out/bin/yoq" YOQ_RECOVERY_BUNDLES=1 bash scripts/agent-recovery-smoke.sh
```

the fixture needs `unshare`, `nsenter`, iproute2, iptables, python3, and wireguard kernel support. it uses local dummy credentials and a failing local registry, so it does not pull an external image. its private artifact directory retains voter state and credentials; the ci recovery-log artifact contains only logs and the result summary. failed runs also retain the executable briefly for local reproduction.
