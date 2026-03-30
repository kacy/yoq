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

## http-routing

two services behind the built-in HTTP router. requests for `demo.local/api` go to the API service, and everything else for `demo.local` goes to the web service.

```bash
yoq serve --http-proxy-bind 127.0.0.1 --http-proxy-port 17080
yoq up -f examples/http-routing/manifest.toml
curl -H 'Host: demo.local' http://127.0.0.1:17080/
curl -H 'Host: demo.local' http://127.0.0.1:17080/api/get
```

## cluster

a multi-node deployment with postgres, API server, nginx with automatic TLS, and a database backup cron. this example now matches the canonical cluster workflow: bootstrap with `init-server`, join agents, then deploy with `yoq up --server`.

```bash
TOKEN=$(openssl rand -hex 32)
yoq init-server --id 1 --port 9700 --api-port 7700 --token "$TOKEN"
yoq join 10.0.0.1:7700 --token "$TOKEN"
yoq up --server 10.0.0.1:7700 -f examples/cluster/manifest.toml
```

see [examples/cluster/README.md](cluster/README.md) for full setup instructions.

## writing your own manifest

a manifest is a TOML file with `[service.*]`, `[worker.*]`, `[cron.*]`, and `[volume.*]` sections. see the [manifest spec](../docs/manifest-spec.md) for the full reference.
