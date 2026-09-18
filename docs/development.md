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

## cluster process drills

ci runs `agent-recovery` with real server and agent processes. the scheduled cluster lane also runs the drain fixture. run both on a disposable linux host after building the runtime helpers; these commands run sequentially and print their artifact directories:

```bash
make test-runtime-cluster
sudo env YOQ_BIN="$PWD/zig-out/bin/yoq" YOQ_RECOVERY_BUNDLES=1 bash scripts/agent-recovery-smoke.sh
sudo env YOQ_BIN="$PWD/zig-out/bin/yoq" bash scripts/agent-drain-smoke.sh
```

the recovery fixture needs `unshare`, `nsenter`, iproute2, iptables, python3, and wireguard kernel support. it uses local dummy credentials and a failing local registry, so it does not pull an external image. its private artifact directory retains voter state and credentials; the ci recovery-log artifact contains only logs and the result summary. failed runs also retain the executable briefly for local reproduction.

the drain fixture also needs curl, openssl, and the built `yoq-test-http-server` helper. it serves its test image from a local fixture registry.

the recovery fixture exercises three voting servers, agent restart, durable result delivery, and offline bundle restore. it also brings a stopped voter back after 65 commands of roughly 20 kib each and checks that a subsequent small write reaches that voter. the drain fixture uses two workers and a live service to check blocked capacity, replacement readiness, a leader restart during handoff, and source agent shutdown after `drained`.

save the binary hash, command output, and fixture artifacts for the revision being reviewed. report the result of each fixture invocation separately. cloud and physical gpu acceptance require the separate procedures in the [gcp validation guide](gcp-cluster-validation.md) and [gpu validation guide](gpu-validation.md).
