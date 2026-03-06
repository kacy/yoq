# cluster example

a multi-node deployment with postgres, an API server, and nginx with automatic TLS.

## setup

### 1. start the server

on your first node, start the control plane:

```bash
yoq serve --port 7700
```

this creates an API token at `~/.local/share/yoq/api_token`.

### 2. join worker nodes

on each additional node, join the cluster:

```bash
yoq join <server-ip>:7700 --token <api-token>
```

the join creates a wireguard tunnel automatically — containers on different nodes can reach each other by name.

### 3. deploy

```bash
# run database migrations
yoq run-worker -f manifest.toml migrate

# start all services
yoq up -f manifest.toml
```

the scheduler places containers across nodes based on available resources. services discover each other by name transparently.

### 4. check status

```bash
yoq nodes          # list cluster nodes
yoq ps             # list running containers
yoq status         # cluster overview
```

## environment variables

set `DB_PASSWORD` before deploying to override the default database password:

```bash
DB_PASSWORD=supersecret yoq up -f manifest.toml
```
