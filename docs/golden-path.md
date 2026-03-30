# golden path

this is the shortest end-to-end way to evaluate yoq as a real platform instead of a pile of disconnected features.

the path has three stages:

1. prove the local runtime and manifest flow
2. prove HTTP routing and observability
3. prove clustered deployment with TLS and service discovery

if a stage fails, stop there and fix that layer before moving on.

## 1. local runtime and manifests

start with the built-in checks:

```bash
yoq doctor
yoq validate -f examples/redis/manifest.toml
yoq validate -f examples/web-app/manifest.toml
yoq validate -f examples/http-routing/manifest.toml
```

then run a local multi-service app:

```bash
yoq up -f examples/web-app/manifest.toml
yoq status
yoq metrics
```

what to verify:

- services start in dependency order
- health checks turn healthy
- status and metrics return sensible output

## 2. HTTP routing and observability

start the API server and HTTP routing listener:

```bash
yoq serve --http-proxy-bind 127.0.0.1 --http-proxy-port 17080
yoq up -f examples/http-routing/manifest.toml
```

send traffic through the built-in router:

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
curl http://127.0.0.1:7700/v1/status?mode=service_discovery
curl http://127.0.0.1:7700/v1/metrics?format=prometheus
```

what to verify:

- host and path routing land on the correct service
- route and listener state appear in `/v1/status?mode=service_discovery`
- Prometheus metrics expose service and routing activity
- the local recovery smoke succeeds without redeploying routes after the listener restart

current limits:

- routed gRPC is prior-knowledge `h2c` only
- one routed HTTP/2 client connection stays pinned to its first matched service

## 3. clustered deployment

follow one authoritative cluster bootstrap path. use `init-server` for servers and `join` for agents.

generate a shared token:

```bash
TOKEN=$(openssl rand -hex 32)
```

start three servers:

```bash
yoq init-server --id 1 --port 9700 --api-port 7700 --token "$TOKEN"
yoq init-server --id 2 --port 9700 --api-port 7700 --peers 1@10.0.0.1:9700 --token "$TOKEN"
yoq init-server --id 3 --port 9700 --api-port 7700 --peers 1@10.0.0.1:9700,2@10.0.0.2:9700 --token "$TOKEN"
```

join agents:

```bash
yoq join 10.0.0.1:7700 --token "$TOKEN"
```

deploy the cluster example:

```bash
DB_PASSWORD=supersecret yoq up --server 10.0.0.1:7700 -f examples/cluster/manifest.toml
```

verify cluster state:

```bash
yoq nodes --server 10.0.0.1:7700
yoq status --server 10.0.0.1:7700
yoq metrics --server 10.0.0.1:7700
```

what to verify:

- all three servers appear and one is leader
- joined agents heartbeat and receive work
- service discovery works across nodes
- the clustered manifest deploys through `yoq up --server`

## 4. failure drills

run these before calling the cluster path healthy.

### leader failover

force the current leader to step down:

```bash
curl -X POST http://10.0.0.1:7700/cluster/step-down \
  -H "Authorization: Bearer $(cat ~/.local/share/yoq/api_token)"
```

what to verify:

- another server becomes leader
- `yoq nodes --server ...` and `yoq status --server ...` still work
- joined agents keep heartbeating without manual reconfiguration

### agent restart and recovery

restart one agent process or reboot one agent node.

what to verify:

- the agent returns to `active`
- cross-node service discovery still works after recovery
- workloads either stay reachable or reconcile back to healthy state

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
- keep port 80 reachable during issuance and renewal
- remember that ACME is HTTP-01 only right now

## what this path is for

this path is the baseline operator story. if these steps are clean, the platform is in good shape for a real small-team deployment. if they are not, fix the workflow, docs, or failure handling before adding more feature breadth.
