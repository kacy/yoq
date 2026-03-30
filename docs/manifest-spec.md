# manifest.toml reference

the manifest file defines multi-service applications. it describes services, workers, cron jobs, and volumes in a single TOML file.

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
| `http_proxy` | table | no | none | shorthand for a single HTTP routing rule |
| `http_routes` | table of tables | no | none | named HTTP routing rules for the service |
| `restart` | string | no | `"none"` | restart policy |
| `tls` | table | no | none | TLS termination configuration |
| `gpu` | table | no | none | GPU passthrough configuration |
| `gpu_mesh` | table | no | none | distributed GPU mesh configuration |
| `alerts` | table | no | none | alert threshold configuration |

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
| `retries` | integer | no | `0` | upstream retries for failed requests |
| `connect_timeout_ms` | integer | no | `1000` | upstream connect timeout in milliseconds |
| `request_timeout_ms` | integer | no | `5000` | upstream request timeout in milliseconds |
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
preserve_host = false
retries = 2
connect_timeout_ms = 1500
request_timeout_ms = 5000
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
```

validation rules:

- each route name must be unique within the service
- host + `path_prefix` pairs must be unique within the service
- `http_proxy` and `http_routes` cannot be used together on the same service

server-side listener defaults:

- `yoq serve` listens on `127.0.0.1:17080`
- `yoq init-server` listens on `0.0.0.0:17080`

override them with:

```text
yoq serve --http-proxy-bind 127.0.0.1 --http-proxy-port 17080
yoq init-server --http-proxy-bind 0.0.0.0 --http-proxy-port 17080
```

use `GET /v1/status?mode=service_discovery` and `GET /v1/metrics?format=prometheus` to inspect listener, route, and steering state. `mode=service_rollout` remains accepted as a compatibility alias.

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

requires `port`. a successful HTTP/2 preface exchange with the target port means healthy.

when a service also uses `http_proxy` or `http_routes`, yoq forwards prior-knowledge HTTP/2 (h2c) traffic end to end for that routed service. this supports unary and streaming gRPC traffic on a single routed connection.

```toml
[service.api.health_check]
type = "grpc"
port = 50051
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
| `acme` | boolean | no | `false` | auto-provision via Let's Encrypt |
| `email` | string | conditional | — | required if `acme = true` |

```toml
[service.web.tls]
domain = "example.com"
acme = true
email = "admin@example.com"
```

for manual certificates, use `yoq cert install` first:

```toml
[service.web.tls]
domain = "example.com"
```

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
