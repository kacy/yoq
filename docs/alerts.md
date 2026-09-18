# service alerts

service alerts run in the local app supervisor and on cluster agents. configure thresholds in the service table:

```toml
[service.api.alerts]
cpu_percent = 90
memory_percent = 85
restart_count = 3
latency_p99_ms = 500
error_rate_percent = 5
webhook = "https://monitoring.example.com/events"
```

samples run every five seconds. a value must exceed its threshold for three consecutive samples before an alert fires. three consecutive samples at or below the threshold resolve it. missing data resets the consecutive-sample count but does not resolve an active alert.

## metric definitions

| metric | measurement |
| --- | --- |
| `cpu_percent` | cpu time consumed since the previous sample, divided by elapsed time and the container's cpu quota. without a quota, 100% means one cpu core. the highest replica value on this host is used. |
| `memory_percent` | current memory usage divided by the container's memory limit. the highest replica value on this host is used. unlimited memory has no percentage and reports unavailable. |
| `restart_count` | successful local supervisor restarts observed during the last 60 seconds, summed across replicas. the initial start is excluded. cluster restart accounting is unavailable. |
| `latency_p99_ms` | nearest-rank p99 of up to 256 completed proxy requests in the last 60 seconds on this host. includes upstream connection and response time. |
| `error_rate_percent` | percentage of those completed requests that returned a 5xx response or failed at the upstream transport. |

cpu and memory stay unavailable if any running replica lacks the required measurement. the first cpu sample establishes a baseline. request metrics stay unavailable when there are no recent completed requests. direct container traffic, mirrored requests, client cancellations, and websocket sessions do not contribute to the request window. http/1 and http/2 proxy requests do.

request history is shared through the same yoq state database on the host, so a proxy in `yoq serve` can supply an app supervisor running in another process. the proxy control plane publishes its bounded history every 15 seconds; an embedded proxy publishes during the five-second alert sampling pass. a flush uses one database transaction for the batch. no request performs a database write. the sampler combines the newest 256 samples across up to eight proxy producers for that service. histories expire after 60 seconds, and a boot identifier prevents reuse after a reboot. the database retains at most 4,096 producer histories.

cluster thresholds apply separately on each hosting agent. they do not calculate a percentile or resource maximum across the cluster. a configured cluster `restart_count` threshold reports `unknown` with `cluster restart accounting unavailable`; it never derives restarts from scaling or deployment changes. other configured metrics continue to run. traffic handled only by a proxy on the coordinator is unavailable to an agent sampler; the coordinator status endpoint collects host results and does not redistribute request samples.

## webhook delivery

webhooks receive a json `POST` over http or https. https uses the system trust store and verifies the hostname. redirects are rejected. each attempt has a ten-second elapsed deadline covering connection setup, tls, request writes, and response headers. response headers are limited to 8 kib. any 2xx response accepts the notification; malformed responses, other status codes, and timeouts appear in alert status.

```json
{"app":"example","service":"api","metric":"cpu_percent","state":"firing","value":96,"threshold":90,"timestamp":1789700000}
```

`state` is `firing` or `resolved`. sustained alerts send reminders every 60 seconds. failed deliveries retry after 60 seconds. a new firing or recovery transition can send immediately. only one delivery runs at a time, independently of metric sampling; services take turns when several notifications are due. a transition observed during an older delivery remains pending.

without `webhook`, thresholds are still evaluated and persisted. delivery reports `disabled`. this is a generic json webhook; receivers that require another schema, including slack incoming webhooks, need an adapter.

## status and limits

`yoq status --alerts` prints the host's persisted alert records as json. use `--app name` to filter them or `--server host:port` to query another host's api. the equivalent endpoint is `GET /v1/status/alerts?app=name`, with `status:read` permission. the agent api exposes the same endpoint using the cluster join token.

`GET /cluster/alerts` collects one page of agent status on the coordinator. each agent remains a separate entry, with a `failure` field if its api cannot be queried. follow `next_offset` using `?offset=...`. pages contain at most eight agents, each with a two-second deadline and a 1 mib response limit. the endpoint requires `cluster:read`; it does not forward the caller's credentials to agents.

local alerts belong to the service supervisor that claimed the current generation. replacing one service retires that service's old thresholds without stopping alerts for the rest of the app. ownership is checked before sampling and delivery; status writes also check ownership in the database. an already-started webhook can finish after replacement, but its result cannot overwrite the new supervisor's status.

records include the latest sample, threshold, active state, sample error, delivery state, delivery error, last successful delivery time, and latest http status. webhook urls and credentials are omitted. rows remain after shutdown, so check `sampled_at` before treating a record as current. a clean supervisor shutdown marks its records `stopped`; a process crash can leave an older state behind. pending deliveries and consecutive-sample counters are in memory and reset when the supervising process restarts.

a process tracks at most 256 active configured services. inactive entries without an in-flight delivery are reclaimed when that limit is reached. proxy request history holds at most 1,024 service names and 256 samples per service. request sampling uses the global service namespace shared by proxy routes. manifests reject service names already owned by another app, so separate apps cannot share a routed service name.
