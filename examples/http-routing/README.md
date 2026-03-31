# http-routing example

this example is the canonical local routing walkthrough.

it starts three echo services behind the built-in router:

- `demo.local/` -> `gateway`
- `demo.local/api/*` with `x-env: canary` -> weighted split across `api` and `api-canary`
- `docs.demo.local/` -> `docs`

start it manually:

```bash
yoq serve --http-proxy-bind 127.0.0.1 --http-proxy-port 17080
yoq up -f examples/http-routing/manifest.toml
curl -H 'Host: demo.local' http://127.0.0.1:17080/
curl -H 'Host: demo.local' -H 'x-env: canary' http://127.0.0.1:17080/api/get
curl -H 'Host: docs.demo.local' http://127.0.0.1:17080/
curl http://127.0.0.1:7700/v1/status?mode=service_discovery
curl http://127.0.0.1:7700/v1/metrics?format=prometheus | rg 'yoq_service_l7_proxy_route_'
```

the `api` route also rewrites `/api/*` to `/*` before forwarding upstream. route selection prefers the longest matching path, then exact header matches, then narrower method filters. when the request method and `x-env: canary` header both match, the route selects from the configured weighted backend list and exposes per-route/backend counters in both status and Prometheus output.

if you want the full local recovery drill, including listener restart and post-restart route recovery, run:

```bash
./scripts/http-routing-recovery-smoke.sh
```

the smoke script runs in an isolated temporary home directory so it does not reuse your normal local yoq state.
