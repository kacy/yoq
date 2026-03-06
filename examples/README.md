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

## writing your own manifest

a manifest is a TOML file with `[service.*]`, `[worker.*]`, `[cron.*]`, and `[volume.*]` sections. see the [manifest spec](../src/manifest/spec.zig) for the full type definitions and the [loader](../src/manifest/loader.zig) for parsing details.
