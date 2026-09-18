# cluster example

a small multi-node deployment with postgres, an API service, nginx, automatic TLS, and an hourly backup cron.

this example follows the same cluster workflow as the main [cluster guide](../../docs/cluster-guide.md) and the [golden path](../../docs/golden-path.md).

## 1. bootstrap the control plane

generate the token once and copy it securely to all three server hosts. run each command on its matching host. each command lists the other two voters; membership cannot be expanded by starting a peerless server first:

```bash
TOKEN=$(openssl rand -hex 32)

sudo -H yoq init-server --id 1 --port 9700 --api-port 7700 --peers 2@10.0.0.2:9700,3@10.0.0.3:9700 --token "$TOKEN"
sudo -H yoq init-server --id 2 --port 9700 --api-port 7700 --peers 1@10.0.0.1:9700,3@10.0.0.3:9700 --token "$TOKEN"
sudo -H yoq init-server --id 3 --port 9700 --api-port 7700 --peers 1@10.0.0.1:9700,2@10.0.0.2:9700 --token "$TOKEN"
```

## 2. join worker nodes

on each agent node:

```bash
sudo -H yoq join 10.0.0.1:7700 --token "$TOKEN"
```

## 3. deploy the manifest

```bash
sudo -H env DB_PASSWORD=supersecret yoq up --server 10.0.0.1:7700 -f examples/cluster/manifest.toml
```

## 4. verify

```bash
sudo -H yoq nodes --server 10.0.0.1:7700
sudo -H yoq status --server 10.0.0.1:7700
sudo -H yoq metrics --server 10.0.0.1:7700
```

## notes

- open ports 80 and 443 on the node serving `myapp.example.com` if you want ACME issuance to succeed
- set `DB_PASSWORD` before deploying to override the default database password
- the manifest includes services and an hourly backup cron; deploy it as one app with the remote manifest workflow
