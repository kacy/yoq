# command reference

these commands describe the current source tree. use `yoq help` for the commands available in your installed version.

local runtime commands require root privileges. keep the same user and home directory when reading their state. the [quickstart](../README.md#run-a-small-app) uses `sudo -H` for this purpose.

## containers

```text
yoq run <image|rootfs> [command]     run a container
yoq ps [--json]                      list containers
yoq stop <id|name>                   stop a container
yoq rm <id|name>                     remove a stopped container
yoq logs <id|name> [--tail N]        show container output
yoq restart <id|name>                restart a container
yoq exec <id|name> <cmd> [args...]   run a command in a container
```

## images

```text
yoq pull <image>                     pull from a registry
yoq push <source> [target]           push to a registry
yoq images [--json]                  list local images
yoq inspect <image>                  show image metadata
yoq rmi <image>                      remove an image
yoq prune [--json]                   delete unreferenced blobs and layers
```

## build and manifests

```text
yoq build [-t tag] [-f Dockerfile] . build an image
                  [--format toml]   build from a toml manifest
yoq up [-f manifest.toml]            start services from a manifest
yoq up [service...]                  start named services and dependencies
yoq up --dev                         watch and hot-restart on changes
yoq up --skip-preflight              bypass local manifest readiness checks
yoq up --server host:port            deploy to a cluster
yoq down [-f manifest.toml]          stop services from a manifest
yoq run-worker <name>                run a one-shot worker
yoq run-worker --server host:port <name>
yoq init [-f path]                   scaffold a manifest
yoq validate [-f manifest.toml] [-q] validate a manifest
```

## deployment and operations

```text
yoq rollback <service>               print the saved service rollback config
yoq rollback --app [name]            re-apply the previous successful app release
yoq rollback --app [name] [--release <id>] [--print]
yoq rollback --app [name] --server host:port [--release <id>] [--print]
yoq history <service>                show service deployment history
yoq history --app [name]             show local app release history
yoq history --app [name] --server host:port [--json]
                                     show remote app release history
yoq status [--verbose]               show service status and resources
yoq status --app [name]              show local app release status
yoq status --app [name] --server host:port
                                     show remote app release status
yoq apps [--json] [--status s|--failed|--in-progress]
                                     list local app release summaries
yoq apps --server host:port [--json] [--status s|--failed|--in-progress]
                                     list remote app release summaries
yoq rollout pause --app [name]       pause an active app rollout
yoq rollout resume --app [name]      resume an active or stored app rollout
yoq rollout cancel --app [name]      cancel an active app rollout
yoq rollout <...> --server host:port control remote app rollouts
yoq metrics [service]                show service metrics
yoq metrics --pairs                  show service-to-service metrics
yoq policy deny <src> <tgt>          block traffic between services
yoq policy allow <src> <tgt>         allow traffic between services
yoq policy rm <src> <tgt>            remove a policy rule
yoq policy list                      list policy rules
```

for app rollbacks, omitting `--release` picks the previous successful release before the current one. use `--print` to inspect the selected stored app snapshot without applying it.
for app rollouts, status and history expose a nested `rollout` view with rollout state, control state, target counts, failure details, and checkpoint data. the older top-level fields are still there for compatibility.

## secrets and certificates

```text
yoq secret set <name> [--value <value>]
                                     store a secret from the flag or stdin
yoq secret get <name>                read a secret
yoq secret rm <name>                 delete a secret
yoq secret list                      list secrets
yoq secret rotate <name>             rotate a secret
yoq cert provision <domain> [--email <email>] [--staging] [--dns-provider <provider>]
                                     provision a TLS certificate via acme
yoq cert renew <domain> [--email <email>] [--staging] [--dns-provider <provider>]
                                     renew a TLS certificate via acme
yoq cert install <domain> --cert <path> --key <path>
yoq cert service <name>              inspect a service certificate
yoq cert list [--json]               list certificates
yoq cert rm <domain>                 remove a certificate
```

if `--email` is omitted for the standalone acme flow, yoq uses `YOQ_ACME_EMAIL` when set and otherwise falls back to `admin@<domain>`.
dns-01 supports built-in `cloudflare`, `route53`, and `gcloud` providers plus an `exec` fallback. provider credentials are referenced through `yoq secret` entries rather than embedded directly in manifests.
before yoq opens an acme order, it checks the local challenge config and referenced dns secrets. `yoq cert list --json` shows renewal metadata for managed certificates: challenge type, provider, directory url, and dns polling settings.

## access and audit logs

```text
yoq token create <name> --scope <scope> [--ttl 30d]
                                     create a scoped api token
yoq token list                      list tokens
yoq token revoke <name>              revoke a token
yoq audit [--server host:port] [--limit N] [--json]
                                     read audit entries from the api server
```

## server and cluster

```text
yoq serve [--port PORT] [--http-proxy-bind ADDR] [--http-proxy-port PORT]
                                     start the api server
yoq init-server [--id N] [--port P]  start a cluster server node
    [--api-port P] [--peers ...]
    [--token TOKEN] [--http-proxy-bind ADDR]
    [--http-proxy-port PORT]
yoq join <host> --token <token>      join as an agent node
yoq cluster status                   show cluster health
yoq nodes [--server host:port]       list agent nodes
yoq drain <id> [--server host:port]  drain an agent node
```

## gpu

```text
yoq gpu topo [--json]                show gpu topology
yoq gpu bench [--gpus N]             gpu-to-gpu bandwidth benchmark
    [--size BYTES] [--iterations N]
```

## training

```text
yoq train start [--server host:port] <name>              start a training job
yoq train status [--server host:port] <name>             show training job status
yoq train stop [--server host:port] <name>               stop a training job
yoq train pause [--server host:port] <name>              pause a training job
yoq train resume [--server host:port] <name>             resume a paused job
yoq train scale [--server host:port] <name> --gpus <n>   scale training ranks
yoq train logs [--server host:port] <name> [--rank N]    show logs for a training rank
```

for clustered training logs, the control plane proxies log reads to the agent that hosts the selected rank. if that agent is unreachable or does not expose the log endpoint, the api returns an explicit hosting-agent error instead of an empty result.

## diagnostics

```text
yoq doctor [-f manifest.toml] [--json]
                                     check system and manifest readiness
yoq backup [--output path]           backup database state
yoq restore <path>                   restore database from backup
```

## meta

```text
yoq version [--json]                 print version
yoq help                             show help
yoq completion <bash|zsh|fish>       output shell completion
```

notes:

- `--json` is available on `ps`, `images`, `prune`, `version`, `gpu topo`, and `doctor`. `yoq doctor -f manifest.toml --json` groups system and manifest checks separately.
- local `yoq up` runs manifest readiness checks before starting services; use `--skip-preflight` only when you need to bypass a known local preflight failure.
- crons defined in the manifest start automatically with `yoq up`.
- deployment, metrics, and certificate commands also support `--server host:port`.
- clustered manifest deploys go through the app-first `/apps/apply` api and carry services, workers, crons, and training definitions in one app snapshot. the older `/deploy` route is still there for legacy callers.
- remote app applies register active cron schedules in cluster state, and `yoq apps` / `yoq status --app` include live training runtime summaries for the current app.
