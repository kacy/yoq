# http-routing example

this example is the canonical local routing walkthrough.

it starts three echo services behind the built-in router:

- `demo.local/` -> `gateway`
- `demo.local/api/*` -> `api`
- `docs.demo.local/` -> `docs`

start it manually:

```bash
yoq serve --http-proxy-bind 127.0.0.1 --http-proxy-port 17080
yoq up -f examples/http-routing/manifest.toml
curl -H 'Host: demo.local' http://127.0.0.1:17080/
curl -H 'Host: demo.local' http://127.0.0.1:17080/api/get
curl -H 'Host: docs.demo.local' http://127.0.0.1:17080/
curl http://127.0.0.1:7700/v1/status?mode=service_discovery
```

if you want the full local recovery drill, including listener restart and post-restart route recovery, run:

```bash
./scripts/http-routing-recovery-smoke.sh
```

the smoke script runs in an isolated temporary home directory so it does not reuse your normal local yoq state.
