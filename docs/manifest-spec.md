# manifest.toml reference

the manifest file defines applications. it describes services, workers, cron jobs, training jobs, and volumes in a single TOML file.

## quick example

```toml
[service.web]
image = "myapp:latest"
command = ["node", "server.js"]
ports = ["80:3000"]
env = ["NODE_ENV=production"]
depends_on = ["db"]

[service.web.health_check]
type = "http"
path = "/health"
port = 3000

[service.web.rollout]
strategy = "rolling"
parallelism = 2
delay_between_batches = "5s"
failure_action = "rollback"
health_check_timeout = "20s"

[service.db]
image = "postgres:16"
ports = ["5432:5432"]
env = ["POSTGRES_PASSWORD=${DB_PASSWORD:-secret}"]
volumes = ["pgdata:/var/lib/postgresql/data"]

[volume.pgdata]
driver = "local"
```

run with `yoq up`, stop with `yoq down`.

---

## services

services are long-running processes. defined under `[service.<name>]`.

| field | type | required | default | description |
|-------|------|----------|---------|-------------|
| `image` | string | yes | — | OCI image reference (e.g. `nginx:latest`) |
| `command` | array of strings | no | image default | container entrypoint |
| `ports` | array of strings | no | `[]` | port mappings (`"host:container"`) |
| `env` | array of strings | no | `[]` | environment variables (`KEY=VALUE`) |
| `depends_on` | array of strings | no | `[]` | services to start first |
| `working_dir` | string | no | image default | working directory inside container |
| `volumes` | array of strings | no | `[]` | volume mounts (`"source:target"`) |
| `health_check` | table | no | none | health probe configuration |
| `rollout` | table | no | none | rollout policy for replacement applies |
| `http_proxy` | table | no | none | shorthand for a single HTTP routing rule |
| `http_routes` | table of tables | no | none | named HTTP routing rules for the service |
| `restart` | string | no | `"none"` | restart policy |
| `tls` | table | no | none | TLS termination configuration |
| `gpu` | table | no | none | GPU passthrough configuration |
| `gpu_mesh` | table | no | none | distributed GPU mesh configuration |
| `alerts` | table | no | none | alert threshold configuration |

services participate in app releases. local `yoq up` and remote `yoq up --server` both normalize the manifest into one app snapshot, store that snapshot in release history, and then execute the service portion of the release. services are the workload kind that roll out automatically on apply.

### ports

format: `"host_port:container_port"`. both must be 1-65535.

```toml
ports = ["80:8080", "443:8443"]
```

### environment variables

format: `KEY=VALUE`. supports variable expansion:

| syntax | behavior |
|--------|----------|
| `${VAR}` | replaced with env var, empty if unset |
| `${VAR:-default}` | replaced with env var, or `default` if unset |
| `$$` | literal `$` |

```toml
env = [
    "DATABASE_URL=postgres://db:5432/${DB_NAME:-myapp}",
    "API_KEY=${API_KEY}",
]
```

### volumes

format: `"source:target"`.

source type is auto-detected:
- starts with `/`, `./`, or `../` — **bind mount** (host directory)
- anything else — **named volume** (managed by yoq)

```toml
volumes = [
    "./src:/app",         # bind mount
    "data:/var/data",     # named volume
]
```

### restart policy

| value | behavior |
|-------|----------|
| `"none"` | don't restart (default) |
| `"always"` | restart unconditionally |
| `"on_failure"` | restart on non-zero exit code |

```toml
restart = "on_failure"
```

### rollout policy

defined under `[service.<name>.rollout]`.

| field | type | required | default | description |
|-------|------|----------|---------|-------------|
| `strategy` | string | no | `"rolling"` | rollout mode: `"rolling"`, `"canary"`, or `"blue_green"` |
| `parallelism` | integer | no | `1` | targets to advance at once for rolling batches |
| `delay_between_batches` | string | no | `"0s"` | wait between rollout batches |
| `failure_action` | string | no | `"pause"` | what to do when a later batch fails: `"pause"` or `"rollback"` |
| `health_check_timeout` | string | no | `"0s"` | readiness gate timeout; `0s` disables rollout health gating |

```toml
[service.web.rollout]
strategy = "canary"
parallelism = 3
delay_between_batches = "10s"
failure_action = "rollback"
health_check_timeout = "30s"
```

strategy behavior:

- `rolling` updates batches using `parallelism`
- `canary` updates one target first, then continues with the configured `parallelism`
- `blue_green` schedules one readiness-gated full batch and cuts over only after the batch is ready

failure action behavior:

- `pause` leaves the rollout blocked for operator action
- `rollback` restores earlier cut-over targets when a later batch fails

readiness behavior:

- when `health_check_timeout = "0s"`, rollout health gating is disabled
- when enabled, local and cluster rollouts wait for service readiness before cutover completes
- in cluster mode, readiness comes from assignment startup plus agent-side service health when a health check is configured

---

## HTTP routing

define either:
- `[service.<name>.http_proxy]` for a single route
- `[service.<name>.http_routes.<route_name>]` for multiple named routes on one service

the upstream target is the first service port in `ports`. `http_proxy` is just shorthand for one route named `default`.

| field | type | required | default | description |
|-------|------|----------|---------|-------------|
| `host` | string | yes | — | hostname to match |
| `path_prefix` | string | no | `"/"` | path prefix to match |
| `rewrite_prefix` | string | no | none | replace the matched prefix before forwarding upstream |
| `match_methods` | array of strings | no | `[]` | allowed HTTP methods, chosen from `GET`, `HEAD`, `POST`, `PUT`, `DELETE` |
| `match_headers` | array of strings | no | `[]` | exact header matches in `name=value` form |
| `backend_services` | array of strings | no | owning service at `100` | weighted backend targets in `service=weight` form |
| `mirror_service` | string | no | none | best-effort shadow copy target; does not affect the client response |
| `retries` | integer | no | `0` | upstream retries for failed requests |
| `connect_timeout_ms` | integer | no | `1000` | upstream connect timeout in milliseconds |
| `request_timeout_ms` | integer | no | `5000` | upstream request timeout in milliseconds |
| `http2_idle_timeout_ms` | integer | no | `30000` | idle timeout for routed downstream HTTP/2 connections |
| `preserve_host` | boolean | no | `true` | forward the original `Host` header instead of the upstream host |

```toml
[service.web]
image = "nginx:alpine"
ports = ["8080:80"]

[service.web.http_proxy]
host = "demo.local"
path_prefix = "/"

[service.api]
image = "mccutchen/go-httpbin:latest"
ports = ["8081:8080"]

[service.api.http_proxy]
host = "demo.local"
path_prefix = "/api"
rewrite_prefix = "/"
match_headers = ["x-env=canary"]
backend_services = ["api=90", "api-canary=10"]
mirror_service = "api-shadow"
preserve_host = false
retries = 2
connect_timeout_ms = 1500
request_timeout_ms = 5000
http2_idle_timeout_ms = 30000
```

multiple routes on one service:

```toml
[service.gateway]
image = "ghcr.io/example/gateway:latest"
ports = ["8080:8080"]

[service.gateway.http_routes.api]
host = "demo.local"
path_prefix = "/api"

[service.gateway.http_routes.admin]
host = "demo.local"
path_prefix = "/admin"
preserve_host = false

[service.gateway.http_routes.canary]
host = "demo.local"
path_prefix = "/api"
match_methods = ["GET", "POST"]
match_headers = ["x-env=canary"]
backend_services = ["api=90", "api-canary=10"]
```

validation rules:

- each route name must be unique within the service
- exact route matches are deduplicated by `host` + `path_prefix` + the full `match_methods` and `match_headers` sets
- `http_proxy` and `http_routes` cannot be used together on the same service
- route matching prefers the longest `path_prefix`, then the route with more exact header conditions, then the route with the narrower method set, then the first defined route
- `backend_services` weights must sum to `100`
- `mirror_service` cannot point at the owning service or one of the configured `backend_services`
- weighted backend selection is deterministic per request key, and retry attempts can move to a different configured backend target
- `mirror_service` is best-effort shadow traffic only: mirror failures are exposed in route traffic counters but do not change the client response or route degraded state

server-side listener defaults:

- `yoq serve` listens on `127.0.0.1:17080`
- `yoq init-server` listens on `0.0.0.0:17080`

override them with:

```text
yoq serve --http-proxy-bind 127.0.0.1 --http-proxy-port 17080
yoq init-server --http-proxy-bind 0.0.0.0 --http-proxy-port 17080
```

use `GET /v1/status?mode=service_discovery`, `GET /v1/services/<name>/proxy-routes`, and `GET /v1/metrics?format=prometheus` to inspect listener, route, steering, weighted-backend traffic, and mirror traffic state. `mode=service_rollout` remains accepted as a compatibility alias.

for weighted and mirrored routes, the JSON service and status payloads include aggregate `traffic`, per-backend `backend_traffic`, aggregate `mirror_traffic`, and per-backend `mirror_backend_traffic` counters. Prometheus exposes `yoq_service_l7_proxy_route_*` counters labeled by route, owning service, selected backend service, and `traffic_role=primary|mirror`.

current HTTP/2 and gRPC routing limits:

- the routing listener accepts plaintext HTTP/2 through prior-knowledge `h2c` and HTTP/1.1 `Upgrade: h2c`; TLS/ALPN HTTP/2 routing works through the TLS terminator when the routed host matches `service.<name>.tls.domain`

---

## health checks

defined under `[service.<name>.health_check]`.

| field | type | required | default | description |
|-------|------|----------|---------|-------------|
| `type` | string | yes | — | `"http"`, `"tcp"`, `"grpc"`, or `"exec"` |
| `interval` | integer | no | `10` | seconds between checks |
| `timeout` | integer | no | `5` | seconds before check times out |
| `retries` | integer | no | `3` | consecutive failures before unhealthy |
| `start_period` | integer | no | `0` | grace period after container start (seconds) |

### http checks

requires `path` and `port`. a 2xx response means healthy.

```toml
[service.web.health_check]
type = "http"
path = "/health"
port = 8080
interval = 15
timeout = 3
```

### tcp checks

requires `port`. a successful TCP connection means healthy.

```toml
[service.db.health_check]
type = "tcp"
port = 5432
```

### grpc checks

requires `port`. yoq sends `grpc.health.v1.Health/Check` over HTTP/2 and requires a `SERVING` response. `service` is optional and defaults to the empty service name.

when a service also uses `http_proxy` or `http_routes`, yoq forwards plaintext HTTP/2 traffic end to end for that routed service, including both prior-knowledge `h2c` and HTTP/1.1 `Upgrade: h2c`. if the same host is also declared under `[service.<name>.tls]`, the TLS proxy can terminate HTTPS, negotiate ALPN `h2`, and forward the decrypted traffic into that routed service. this supports unary and streaming gRPC traffic on a single routed connection, subject to the HTTP/2 routing limits above.

```toml
[service.api.health_check]
type = "grpc"
port = 50051
service = "pkg.Health"
interval = 5
timeout = 2
```

### exec checks

requires `command`. exit code 0 means healthy.

```toml
[service.cache.health_check]
type = "exec"
command = ["redis-cli", "ping"]
```

---

## TLS configuration

defined under `[service.<name>.tls]`. enables TLS termination with automatic or manual certificates.

| field | type | required | default | description |
|-------|------|----------|---------|-------------|
| `domain` | string | yes | — | domain name for the certificate |

ACME is enabled by adding `[service.<name>.tls.acme]`.

| field | type | required | default | description |
|-------|------|----------|---------|-------------|
| `email` | string | yes | — | ACME account email |
| `staging` | boolean | no | `false` | use the Let's Encrypt staging directory |
| `directory_url` | string | no | production Let's Encrypt | custom ACME directory URL; cannot be combined with `staging` |
| `challenge` | string | no | `"http-01"` | `http-01` or `dns-01` |

DNS-01 settings live under `[service.<name>.tls.acme.dns]`.

| field | type | required | default | description |
|-------|------|----------|---------|-------------|
| `provider` | string | yes | — | `cloudflare`, `route53`, `gcloud`, or `exec` |
| `secrets` | string array | no | `[]` | provider credential references in `key=secret-name` form |
| `config` | string array | no | `[]` | provider-specific non-secret config in `key=value` form |
| `hook` | string array | conditional | `[]` | exec fallback command and arguments |
| `propagation_timeout_secs` | integer | no | `300` | DNS TXT propagation timeout |
| `poll_interval_secs` | integer | no | `5` | DNS TXT polling interval |

```toml
[service.web.tls]
domain = "example.com"

[service.web.tls.acme]
email = "admin@example.com"
```

automatic certificate management uses ACME HTTP-01 validation. the host running the TLS proxy must be reachable on port 80 while the certificate is being issued or renewed.

DNS-01 is also supported:

```toml
[service.web.tls]
domain = "example.com"

[service.web.tls.acme]
email = "admin@example.com"
challenge = "dns-01"

[service.web.tls.acme.dns]
provider = "cloudflare"
secrets = ["api_token=cf-acme-token"]
config = ["zone_id=zone-123"]
```

Built-in DNS-01 providers:

- `cloudflare`: secret ref `api_token`, config `zone_id`
- `route53`: secret refs `access_key_id` and `secret_access_key`, config `hosted_zone_id`, optional config `region`
- `gcloud`: secret ref `access_token`, config `project` and `managed_zone`
- `exec`: `hook = ["/path/to/hook", "arg1", ...]`; `secrets` become environment variables passed to the hook

yoq validates these local settings before opening an ACME order. missing provider keys, missing referenced secrets, empty exec hooks, and invalid DNS polling intervals fail early with a configuration error.

for manual certificates, use `yoq cert install` first:

```toml
[service.web.tls]
domain = "example.com"
```

standalone certificate commands:

```text
yoq cert provision example.com
yoq cert renew example.com
yoq cert provision example.com --dns-provider cloudflare --dns-secret api_token=cf-acme-token --dns-config zone_id=zone-123
yoq cert list --json
```

`--email` remains available for the standalone ACME flow. When it is omitted, yoq uses `YOQ_ACME_EMAIL` when set and otherwise falls back to `admin@<domain>`.

current limits:

- `http-01` still requires this host to bind port 80 and serve the challenge path
- `dns-01` depends on explicit provider config and the referenced `yoq secret` entries

---

## GPU configuration

defined under `[service.<name>.gpu]`. requests GPU passthrough for the container.

| field | type | required | default | description |
|-------|------|----------|---------|-------------|
| `count` | integer | no | `0` | number of GPUs to allocate |
| `model` | string | no | none | GPU model filter (e.g. `"A100"`, `"H100"`) |
| `vram_min_mb` | integer | no | none | minimum VRAM per GPU in MB |

```toml
[service.inference.gpu]
count = 2
model = "A100"
vram_min_mb = 40000
```

---

## GPU mesh configuration

defined under `[service.<name>.gpu_mesh]`. configures distributed GPU communication (NCCL) for multi-rank workloads.

| field | type | required | default | description |
|-------|------|----------|---------|-------------|
| `world_size` | integer | yes | — | total number of ranks |
| `gpus_per_rank` | integer | no | `1` | GPUs assigned to each rank |
| `master_port` | integer | no | `29500` | NCCL master coordination port |

```toml
[service.trainer.gpu_mesh]
world_size = 8
gpus_per_rank = 4
master_port = 29500
```

---

## alerts

defined under `[service.<name>.alerts]`. threshold-based monitoring with webhook notifications. when a metric exceeds its threshold for consecutive checks, the webhook is fired.

| field | type | required | default | description |
|-------|------|----------|---------|-------------|
| `cpu_percent` | float | no | none | CPU usage threshold (0-100) |
| `memory_percent` | float | no | none | memory usage threshold (0-100) |
| `restart_count` | integer | no | none | restart count threshold |
| `latency_p99_ms` | float | no | none | p99 latency threshold in ms |
| `error_rate_percent` | float | no | none | error rate threshold (0-100) |
| `webhook` | string | no | none | webhook URL for notifications |

```toml
[service.web.alerts]
cpu_percent = 90
memory_percent = 85
restart_count = 5
latency_p99_ms = 500
webhook = "https://hooks.slack.com/services/T.../B.../xxx"
```

---

## workers

workers are one-shot tasks that run to completion. defined under `[worker.<name>]`.

| field | type | required | default | description |
|-------|------|----------|---------|-------------|
| `image` | string | yes | — | OCI image reference |
| `command` | array of strings | no | image default | command to execute |
| `env` | array of strings | no | `[]` | environment variables |
| `depends_on` | array of strings | no | `[]` | services/workers to run first |
| `working_dir` | string | no | image default | working directory |
| `volumes` | array of strings | no | `[]` | volume mounts |
| `gpu` | table | no | none | GPU passthrough (same fields as service GPU) |
| `gpu_mesh` | table | no | none | GPU mesh (same fields as service GPU mesh) |

```toml
[worker.migrate]
image = "myapp:latest"
command = ["python", "manage.py", "migrate"]
depends_on = ["db"]
env = ["DATABASE_URL=postgres://db:5432/myapp"]
```

run with `yoq run-worker migrate`.

workers are part of the app snapshot and release history, but `yoq up` does not run them automatically. use `yoq run-worker <name>` locally or `yoq run-worker --server host:port <name>` against a cluster to execute a worker from the current app release.

---

## cron jobs

cron jobs run on a recurring schedule. defined under `[cron.<name>]`.

| field | type | required | default | description |
|-------|------|----------|---------|-------------|
| `image` | string | yes | — | OCI image reference |
| `command` | array of strings | no | image default | command to execute |
| `every` | string | yes | — | interval (`"30s"`, `"5m"`, `"1h"`) |
| `env` | array of strings | no | `[]` | environment variables |
| `working_dir` | string | no | image default | working directory |
| `volumes` | array of strings | no | `[]` | volume mounts |

```toml
[cron.cleanup]
image = "myapp:latest"
command = ["python", "cleanup.py"]
every = "1h"
```

### duration format

| suffix | meaning |
|--------|---------|
| `s` | seconds |
| `m` | minutes |
| `h` | hours |

examples: `"30s"`, `"5m"`, `"1h"`, `"24h"`.

cron definitions are stored in the app release snapshot. local and clustered app applies register or update the active cron schedule set from the current release, and rollback restores the cron definitions from the selected release.

---

## training jobs

training jobs orchestrate distributed GPU training runs. defined under `[training.<name>]`.

| field | type | required | default | description |
|-------|------|----------|---------|-------------|
| `image` | string | yes | — | OCI image reference |
| `command` | array of strings | no | image default | command to execute |
| `env` | array of strings | no | `[]` | environment variables |
| `working_dir` | string | no | image default | working directory |
| `volumes` | array of strings | no | `[]` | volume mounts |
| `gpus` | integer | yes | — | total number of GPUs (= number of ranks) |
| `gpu_type` | string | no | none | GPU model filter (e.g. `"H100"`) |
| `data` | table | no | none | dataset configuration |
| `checkpoint` | table | no | none | checkpoint configuration |
| `resources` | table | no | see below | resource limits per rank |
| `fault_tolerance` | table | no | see below | fault tolerance settings |

```toml
[training.llm-finetune]
image = "trainer:v2"
command = ["torchrun", "train.py"]
gpus = 8
gpu_type = "H100"
env = ["EPOCHS=10", "BATCH_SIZE=32"]
```

### data configuration

defined under `[training.<name>.data]`.

| field | type | required | default | description |
|-------|------|----------|---------|-------------|
| `dataset` | string | yes | — | dataset path or identifier |
| `sharding` | string | yes | — | sharding strategy (e.g. `"file"`) |
| `preprocessing` | string | no | none | preprocessing pipeline (e.g. `"tokenize"`) |

```toml
[training.llm-finetune.data]
dataset = "/mnt/lustre/pile"
sharding = "file"
preprocessing = "tokenize"
```

### checkpoint configuration

defined under `[training.<name>.checkpoint]`.

| field | type | required | default | description |
|-------|------|----------|---------|-------------|
| `path` | string | yes | — | checkpoint storage path |
| `interval_secs` | integer | no | `1800` | seconds between checkpoints |
| `keep` | integer | no | `5` | number of checkpoints to retain |

```toml
[training.llm-finetune.checkpoint]
path = "/mnt/checkpoints/llm"
interval_secs = 900
keep = 3
```

### resource configuration

defined under `[training.<name>.resources]`.

| field | type | required | default | description |
|-------|------|----------|---------|-------------|
| `cpu` | integer | no | `1000` | CPU millicores per rank |
| `memory_mb` | integer | no | `65536` | memory limit per rank in MB |
| `ib_required` | boolean | no | `false` | require InfiniBand connectivity |

```toml
[training.llm-finetune.resources]
cpu = 4000
memory_mb = 131072
ib_required = true
```

### fault tolerance configuration

defined under `[training.<name>.fault_tolerance]`.

| field | type | required | default | description |
|-------|------|----------|---------|-------------|
| `spare_ranks` | integer | no | `0` | spare ranks for failover |
| `auto_restart` | boolean | no | `true` | restart failed ranks automatically |
| `max_restarts` | integer | no | `10` | maximum restart attempts per rank |

```toml
[training.llm-finetune.fault_tolerance]
spare_ranks = 1
auto_restart = true
max_restarts = 5
```

training definitions are part of the app snapshot and release history, but `yoq up` does not auto-start training runs. use `yoq train start|status|stop|pause|resume|scale|logs <name>` locally or `yoq train ... --server host:port <name>` against a cluster to operate on training jobs from the current app release.

---

## volumes

named volumes are defined under `[volume.<name>]`.

| field | type | required | default | description |
|-------|------|----------|---------|-------------|
| `driver` | string | no | `"local"` | storage driver |

four volume drivers are available:

### local (default)

managed by yoq. no extra configuration.

```toml
[volume.pgdata]
driver = "local"
```

### host

bind-mount a host directory.

| field | type | required | description |
|-------|------|----------|-------------|
| `path` | string | yes | absolute path on the host |

```toml
[volume.data]
driver = "host"
path = "/srv/data"
```

### nfs

mount an NFS share.

| field | type | required | description |
|-------|------|----------|-------------|
| `server` | string | yes | NFS server hostname or IP |
| `path` | string | yes | export path on the server |
| `options` | string | no | mount options (e.g. `"nolock,hard"`) |

```toml
[volume.shared]
driver = "nfs"
server = "nfs.internal"
path = "/exports/shared"
options = "nolock,hard"
```

### parallel

mount a parallel filesystem (Lustre, GPFS).

| field | type | required | description |
|-------|------|----------|-------------|
| `mount_path` | string | yes | path to the parallel filesystem mount |

```toml
[volume.training-data]
driver = "parallel"
mount_path = "/mnt/lustre/datasets"
```

volumes referenced in service/worker/cron `volumes` arrays that aren't explicitly defined use the default local driver.

---

## dependency ordering

services start in dependency order. if service A `depends_on = ["B"]`, B starts before A.

- circular dependencies are detected and rejected during validation
- self-dependencies are rejected
- unknown dependencies are rejected

use `yoq validate` to check a manifest before deploying.

---

## dev mode

`yoq up --dev` enables hot reload:

- bind-mounted volumes are watched for file changes (inotify)
- services restart automatically when source files change
- logs are multiplexed with colored service name prefixes

this is intended for local development, not production.

---

## related commands

| command | description |
|---------|-------------|
| `yoq init` | create a manifest.toml interactively |
| `yoq validate` | validate manifest syntax and semantics |
| `yoq up` | start all services |
| `yoq up --dev` | start in dev mode with hot reload |
| `yoq up <service>` | start a specific service |
| `yoq down` | stop all services |
| `yoq run-worker <name>` | run a one-shot worker |
| `yoq history <service>` | show deployment history |
| `yoq rollback <service>` | rollback to previous deployment |
