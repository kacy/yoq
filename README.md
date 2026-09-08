# yoq

yoq builds, runs, and deploys containers on linux. image builds, service discovery, health checks, rollouts, secrets, tls, and metrics live in one binary.

describe your app in a toml file and start it with `yoq up`. use the same cli to check its status, inspect release history, and roll back an app update. deploy to a single host or a cluster.

for a small team running several services, keeping these pieces together can reduce the setup and integration work. there are fewer tools to connect, and the configuration for your app stays in one place.

yoq is a young project that is still being hardened. it has a smaller ecosystem than kubernetes, so check the integrations your team needs. test your workloads and recovery procedures before using it in production.

## quickstart

### requirements

- linux kernel 6.1+ with cgroups v2; yoq does not run natively on macos or windows
- root privileges for local container, filesystem, and network setup
- curl, python3, and the github cli (`gh`) with attestation support for the installer
- zig 0.16.0 and make if building from source

### install

```bash
curl -fsSL https://yoq.dev/install | bash
```

the installer selects the latest published [github release](https://github.com/kacy/yoq/releases/latest), checks the archive checksum, and verifies its publisher attestations and release metadata before installing it.

the current v0.2.0 release is missing the provenance file required by this installer. until a release includes the required metadata and attestations, use the source build below.

when run as a regular user, the installer puts `yoq` in `~/.local/bin`; as root, it uses `/usr/local/bin`. add the installation directory to your path if needed.

### build from source

```bash
git clone https://github.com/kacy/yoq.git
cd yoq
make build
sudo install -m 0755 zig-out/bin/yoq /usr/local/bin/yoq
```

### run a small app

save this as `manifest.toml` in your app directory:

```toml
[service.web]
image = "nginx:latest"
ports = ["8080:80"]

[service.web.health_check]
type = "http"
path = "/"
port = 80
```

the commands below use root's home directory so runtime and status commands share the same state. `command -v yoq` resolves the binary even if it was installed in your user's `~/.local/bin`.

```bash
sudo -H "$(command -v yoq)" doctor -f manifest.toml
sudo -H "$(command -v yoq)" up --dry-run -f manifest.toml
sudo -H "$(command -v yoq)" up -f manifest.toml
```

local `yoq up` stays in the foreground. while it runs, open a second terminal in the same app directory:

```bash
curl http://localhost:8080
sudo -H "$(command -v yoq)" apps
sudo -H "$(command -v yoq)" status --app
sudo -H "$(command -v yoq)" history --app
```

press ctrl-c in the first terminal to stop the app. you can also stop it from the second terminal with `sudo -H "$(command -v yoq)" down -f manifest.toml`.

for a larger example with postgres, redis, workers, and health checks, see [examples/web-app](examples/web-app/). the [operator guide](docs/golden-path.md) covers local apps, http routing, and clustered deployment.

## what you get

| area | capabilities |
| --- | --- |
| containers | linux namespace isolation, cgroups v2 limits, overlayfs, seccomp filters, capability dropping, logs, restart handling, and exec |
| images and builds | registry pulls and pushes, dockerfile builds with multiple stages and build args, cached build steps, and an optional toml build format |
| applications | service dependencies, one-shot workers, cron jobs, health checks, readiness probes, and development mode with restarts on file changes |
| deployments | app release history, rollback, rollout policies, pause/resume/cancel controls, and automatic rollback when configured |
| networking | bridge networks, service dns, port mapping, outbound nat, ebpf load balancing and policy enforcement where supported, and wireguard cluster networking |
| operations | encrypted secrets, tls certificates, scoped api tokens, an audit log, optional service-to-service mtls, metrics, webhook alerts, and system checks |

### routing and certificates

http routing supports host, path, method, and header matching, rewrites, weighted backends, and best-effort request mirroring. grpc health checks use `grpc.health.v1.Health/Check`.

http/2 clients can use prior-knowledge `h2c` or `Upgrade: h2c` on the plaintext listener. tls-terminated http/2 uses alpn when the routed host matches a service's `tls.domain`.

acme certificate provisioning and renewal support http-01 and dns-01 challenges. http-01 needs port 80 on the target host. dns-01 needs an explicit provider configuration and credentials stored with `yoq secret`.

see the [command reference](docs/commands.md#secrets-and-certificates) and [routing example](examples/http-routing/).

### clusters

server nodes run raft, the api, and the scheduler. agent nodes run workloads and report their health and resources. server nodes use raft consensus with sqlite-backed state. cluster transport uses hmac-sha256 authentication. yoq also includes gossip failure detection, node drain, and rolling upgrades with leader step-down.

use `yoq up --server <server-ip>:<port>` to deploy an app to an existing cluster. see the [cluster guide](docs/cluster-guide.md) for setup and recovery procedures.

### gpu and training

gpu support targets nvidia linux hosts. it includes device discovery, container passthrough, cluster gang scheduling, and nccl configuration using detected gpu and infiniband topology.

training controls include job status, logs, pause, resume, and checkpoint tracking. applications write and restore their own checkpoints. local distributed training is incomplete; use the [gpu validation guide](docs/gpu-validation.md) to evaluate the paths and hardware you need.

### storage and backups

volumes support local directories, host paths, nfs mounts, and existing parallel filesystem mounts. the local object store implements a subset of the s3 api and uses yoq bearer-token authentication.

`yoq backup` creates an encrypted backup of yoq's database by default. application volumes and object data need separate backups.

## everyday commands

```text
yoq run <image> [command]           run a container
yoq ps                             list containers
yoq logs <id-or-name>               read container output
yoq up -f manifest.toml             start an app
yoq apps                           list apps
yoq status --app [name]             inspect an app
yoq history --app [name]            inspect app release history
yoq rollback --app [name]           apply the previous successful app release
yoq rollout pause --app [name]      pause an app rollout
yoq rollout resume --app [name]     resume an app rollout
yoq rollout cancel --app [name]     cancel an app rollout
yoq doctor                         check the host
yoq help                           show command help
```

local runtime commands need the privileges and state directory used to start the app. the quickstart shows the sudo form. app rollback requires an earlier successful release; `--print` lets you inspect it before applying it. service-level `yoq rollback <service>` prints a saved configuration for manual redeployment.

see the [command reference](docs/commands.md) for image, build, policy, certificate, cluster, and training commands, and the [rollout guide](docs/rollouts.md) for deployment and recovery behavior.

## examples and documentation

- [redis](examples/redis/): a single service with a health check
- [web app](examples/web-app/): postgres, redis, workers, and health checks
- [cron jobs](examples/cron/): scheduled work
- [http routing](examples/http-routing/): route matching and backend selection
- [cluster](examples/cluster/): deployment across nodes
- [manifest reference](docs/manifest-spec.md): configuration fields
- [architecture](docs/architecture.md) and [internals guide](docs/users-guide.md): how the subsystems work
- [development](docs/development.md): build and test commands

## project status

this readme describes the current source tree. published binaries may have fewer features; see the [release notes](https://github.com/kacy/yoq/releases) for the version you install.

work toward v1.0 focuses on reliability, failure testing, and operational improvements. the cli is the primary interface; a web ui is deferred. container image signing is not built in.
