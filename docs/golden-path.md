# golden path

this is the shortest end-to-end path for evaluating yoq.

the path has three stages:

1. prove the local runtime and manifest flow
2. prove HTTP routing and observability
3. prove clustered deployment with app-first day-2 operations

if a stage fails, stop there and fix that layer before moving on.

before running the manual path, `make test-golden-path` checks the same local assumptions that are cheap to automate: CLI startup, example manifest validation, example app shape, and shell-script syntax.

## 1. local runtime and manifests

start with the built-in checks:

```bash
sudo -H "$(command -v yoq)" doctor
sudo -H "$(command -v yoq)" doctor -f examples/web-app/manifest.toml
sudo -H "$(command -v yoq)" doctor -f examples/http-routing/manifest.toml
sudo -H "$(command -v yoq)" validate -f examples/redis/manifest.toml
sudo -H "$(command -v yoq)" validate -f examples/web-app/manifest.toml
sudo -H "$(command -v yoq)" validate -f examples/http-routing/manifest.toml
```

these commands use root-owned state under `/root/.local/share/yoq`. run the local app in one terminal; `up` stays in the foreground:

```bash
sudo -H "$(command -v yoq)" up -f examples/web-app/manifest.toml
```

in another terminal, inspect the app using the same root-owned state:

```bash
sudo -H "$(command -v yoq)" apps
sudo -H "$(command -v yoq)" status --app web-app
sudo -H "$(command -v yoq)" history --app web-app
sudo -H "$(command -v yoq)" metrics
```

what to verify:

- services start in dependency order
- health checks turn healthy
- app status/history make sense for the current release
- metrics return sensible output

## 2. HTTP routing and observability

start the API server and HTTP routing listener:

```bash
sudo -H "$(command -v yoq)" serve --http-proxy-bind 127.0.0.1 --http-proxy-port 17080
```

keep the server running and start the app in another terminal:

```bash
sudo -H "$(command -v yoq)" up -f examples/http-routing/manifest.toml
```

from a third terminal, send traffic through the built-in router:

```bash
curl -H 'Host: demo.local' http://127.0.0.1:17080/
curl -H 'Host: demo.local' http://127.0.0.1:17080/api/get
```

or run the whole local routing drill, including listener restart and recovery:

```bash
./scripts/http-routing-recovery-smoke.sh
```

inspect the routing state:

```bash
curl -H "Authorization: Bearer $(sudo cat /root/.local/share/yoq/api_token)" \
  http://127.0.0.1:7700/v1/status?mode=service_discovery
curl -H "Authorization: Bearer $(sudo cat /root/.local/share/yoq/api_token)" \
  http://127.0.0.1:7700/v1/metrics?format=prometheus
```

what to verify:

- host and path routing land on the correct service
- route and listener state appear in `/v1/status?mode=service_discovery`
- Prometheus metrics expose service and routing activity
- the local recovery smoke succeeds without redeploying routes after the listener restart

current limits:

- routed gRPC supports prior-knowledge `h2c` directly, and HTTPS/ALPN `h2` when the routed host also has a matching `tls.domain`

## 3. clustered deployment

follow one cluster bootstrap path. use `init-server` for servers and `join` for agents.

follow [credential setup](cluster-guide.md#step-1-prepare-credentials) first. it creates separate join and api tokens and installs the api token on each server and operator host. use that shared join token below; do not generate a different value on each host.

run each server command on its matching host, using the same token on all hosts. every server must start with the complete fixed voter set; a peerless server creates a different, single-voter cluster:

```bash
sudo -H "$(command -v yoq)" init-server --id 1 --port 9700 --api-port 7700 --peers 2@10.0.0.2:9700,3@10.0.0.3:9700 --token "$TOKEN"
sudo -H "$(command -v yoq)" init-server --id 2 --port 9700 --api-port 7700 --peers 1@10.0.0.1:9700,3@10.0.0.3:9700 --token "$TOKEN"
sudo -H "$(command -v yoq)" init-server --id 3 --port 9700 --api-port 7700 --peers 1@10.0.0.1:9700,2@10.0.0.2:9700 --token "$TOKEN"
```

join agents:

```bash
sudo -H "$(command -v yoq)" join 10.0.0.1 --port 7700 --token "$TOKEN"
```

query `sudo -H "$(command -v yoq)" cluster status` on the servers to identify the current leader. the following operator commands assume it is `10.0.0.1:7700`; substitute the actual leader address. app deployment does not retry automatically after a leader hint.

deploy the cluster example:

```bash
sudo -H env DB_PASSWORD=supersecret "$(command -v yoq)" up --server 10.0.0.1:7700 -f examples/cluster/manifest.toml
```

verify cluster state:

```bash
sudo -H "$(command -v yoq)" nodes --server 10.0.0.1:7700
sudo -H "$(command -v yoq)" apps --server 10.0.0.1:7700
sudo -H "$(command -v yoq)" status --app cluster --server 10.0.0.1:7700
sudo -H "$(command -v yoq)" history --app cluster --server 10.0.0.1:7700
sudo -H "$(command -v yoq)" metrics --server 10.0.0.1:7700
```

what to verify:

- `sudo -H "$(command -v yoq)" cluster status` on each server shows one leader and the same term; `nodes` lists agents, not voters
- joined agents heartbeat and receive work
- service discovery works across nodes
- the clustered manifest deploys through `yoq up --server`
- app status/history expose current release, previous successful release, and rollout state

## 4. failure drills

run these before calling the cluster path healthy.

### leader failover

force the current leader to step down:

```bash
curl -X POST http://10.0.0.1:7700/cluster/step-down \
  -H "Authorization: Bearer $(sudo cat /root/.local/share/yoq/api_token)"
```

what to verify:

- another server becomes leader
- `yoq nodes --server ...` and `yoq status --server ...` still work
- joined agents keep heartbeating without manual reconfiguration

then repeat the drill with a hard failure: stop the current leader process or disconnect its API port while leaving a voting quorum available. leave that endpoint unavailable while checking recovery; graceful step-down alone does not test a broken connection.

- agents reach a surviving server without changing their join arguments
- agent and node IDs stay unchanged
- assignment polling resumes and terminal results reach the surviving leader
- a late result from an earlier assignment generation cannot stop its replacement

### offline recovery of every voter

on a disposable cluster, stop all voters and agents, capture one `cluster backup` bundle per voter with the same new set ID, and run `cluster verify-set` across all bundles. restore each original voter ID into a fresh data root using the verified fingerprint. follow the [offline recovery procedure](cluster-guide.md#offline-cluster-backup-and-restore) for exact commands and credential handling.

start the restored voters and verify that they elect a leader, retain existing app and agent records, and accept a new committed mutation. then restart an agent with its original enrollment identity and result queue. verify that pending terminal reports are acknowledged and a new assignment can run. also check that a missing voter bundle, changed set ID, corrupt database, and active source are rejected.

### agent restart and recovery

restart one agent process or reboot one agent node.

what to verify:

- the agent returns to `active`
- cross-node service discovery still works after recovery
- interrupted assignment cgroups are stopped before their attempts are reported failed
- a queued terminal result survives the restart and reaches committed state after API connectivity returns
- a stale cached assignment does not launch a second copy

preserve the enrollment directory and `agent-cache.db` throughout this drill. temporarily interrupt the API connection when a short worker exits, restart the agent, restore connectivity, and verify that the original attempt becomes terminal without a duplicate launch.

### rollout pause and resume

for a readiness-gated service release:

```bash
sudo -H "$(command -v yoq)" rollout pause --app cluster --server 10.0.0.1:7700
sudo -H "$(command -v yoq)" status --app cluster --server 10.0.0.1:7700
sudo -H "$(command -v yoq)" rollout resume --app cluster --server 10.0.0.1:7700
```

what to verify:

- `ROLLOUT` shows a blocked state while paused
- `CTRL` shows the paused control state
- the rollout resumes from stored progress instead of starting from zero

### routing listener restart

for a routed deployment, restart the API server or the HTTP routing listener process.

the canonical local version of this drill is `./scripts/http-routing-recovery-smoke.sh`.

what to verify:

- the listener comes back on the configured bind and port
- `/v1/status?mode=service_discovery` shows listener and steering state recovering
- routed traffic succeeds again without manual route repair

### reconcile and drift recovery

introduce one controlled mismatch, then verify recovery:

- stop one service container unexpectedly
- remove one endpoint manually
- restart a node that owns routed workloads

what to verify:

- reconcile counters increase
- discovery and route state converge again
- `/v1/metrics?format=prometheus` exposes the recovery rather than hiding it

## TLS and ACME check

if you want to validate automatic certificates on the cluster example:

- point `myapp.example.com` at the node serving ports 80 and 443
- keep port 80 reachable during issuance and renewal if you use `http-01`
- for `dns-01`, create the referenced `yoq secret` entries first and configure a built-in provider or exec hook in `[service.<name>.tls.acme.dns]`

## what this path is for

this path is the baseline operator flow. if these steps are clean, the platform is in good shape for a small-team deployment. if they are not, fix the workflow, docs, or failure handling before adding more feature breadth.
