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

five services behind the built-in HTTP router. requests for `demo.local/api` with `x-env: canary` use the weighted `api` / `api-canary` backend list, `docs.demo.local` goes to the docs service, and everything else for `demo.local` goes to the gateway service.

```bash
yoq serve --http-proxy-bind 127.0.0.1 --http-proxy-port 17080
yoq up -f examples/http-routing/manifest.toml
curl -H 'Host: demo.local' http://127.0.0.1:17080/
curl -H 'Host: demo.local' -H 'x-env: canary' http://127.0.0.1:17080/api/get
```

for the full restart-and-recovery drill, run `./scripts/http-routing-recovery-smoke.sh`.

see [examples/http-routing/README.md](http-routing/README.md) for the complete walkthrough.

## cluster

a multi-node deployment with postgres, an api service, nginx with automatic tls, and a database backup cron.

follow the [complete cluster setup](cluster/README.md). prepare the shared join token and private api token files, then start the fixed three-voter set with matching peer lists. run the server and agent commands in separate terminals on their respective hosts; they remain in the foreground. use `sudo -H "$(command -v yoq)"` for runtime commands so they share root's state and credentials.

once all voters and agents are ready, deploy from a separate operator terminal with the api token installed. use the current leader's address and supply `DB_PASSWORD` as shown in the complete setup.

## writing your own manifest

a manifest is a TOML file with `[service.*]`, `[worker.*]`, `[cron.*]`, and `[volume.*]` sections. see the [manifest spec](../docs/manifest-spec.md) for the full reference.
