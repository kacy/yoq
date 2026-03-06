# examples

example manifests showing common yoq use cases.

## redis

the simplest possible manifest — a single redis instance with a TCP health check.

```bash
yoq up -f examples/redis/manifest.toml
```

## web-app

a multi-service web application: nginx frontend, python API, postgres database, and redis cache. includes a worker for running database migrations before the API starts.

```bash
# run migrations first
yoq run-worker -f examples/web-app/manifest.toml migrate

# start everything
yoq up -f examples/web-app/manifest.toml
```

## cron

a postgres database with an hourly backup cron. the cron runs `pg_dump` every hour automatically when services are started.

```bash
yoq up -f examples/cron/manifest.toml
```

## cluster

a multi-node deployment with postgres, API server, and nginx with automatic TLS. demonstrates service discovery across nodes, environment variable expansion, and a database backup cron.

```bash
# start the server node
yoq serve --port 7700

# join worker nodes
yoq join <server-ip>:7700 --token <api-token>

# deploy
yoq up -f examples/cluster/manifest.toml
```

see [examples/cluster/README.md](cluster/README.md) for full setup instructions.

## writing your own manifest

a manifest is a TOML file with `[service.*]`, `[worker.*]`, `[cron.*]`, and `[volume.*]` sections. see the [manifest spec](../docs/manifest-spec.md) for the full reference.
