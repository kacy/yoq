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
| `restart` | string | no | `"none"` | restart policy |
| `tls` | table | no | none | TLS termination configuration |

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

## health checks

defined under `[service.<name>.health_check]`.

| field | type | required | default | description |
|-------|------|----------|---------|-------------|
| `type` | string | yes | — | `"http"`, `"tcp"`, or `"exec"` |
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

## volumes

named volumes are defined under `[volume.<name>]`.

| field | type | required | default | description |
|-------|------|----------|---------|-------------|
| `driver` | string | no | `"local"` | storage driver |

```toml
[volume.pgdata]
driver = "local"
```

volumes referenced in service/worker/cron `volumes` arrays that aren't explicitly defined use the default driver.

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
