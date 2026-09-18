# cluster example

a small multi-node deployment with postgres, an API service, nginx, automatic TLS, and an hourly backup cron.

this example follows the same cluster workflow as the main [cluster guide](../../docs/cluster-guide.md) and the [golden path](../../docs/golden-path.md).

## 1. bootstrap the control plane

complete the [credential setup](../../docs/cluster-guide.md#step-1-prepare-credentials) first, including the api token files. use the same join token on all three hosts. run each command on its matching host in a separate terminal; servers and agents stay in the foreground. each command lists the other two voters; membership cannot be expanded by starting a peerless server first:

```bash
sudo -H "$(command -v yoq)" init-server --id 1 --port 9700 --api-port 7700 --peers 2@10.0.0.2:9700,3@10.0.0.3:9700 --token "$TOKEN"
sudo -H "$(command -v yoq)" init-server --id 2 --port 9700 --api-port 7700 --peers 1@10.0.0.1:9700,3@10.0.0.3:9700 --token "$TOKEN"
sudo -H "$(command -v yoq)" init-server --id 3 --port 9700 --api-port 7700 --peers 1@10.0.0.1:9700,2@10.0.0.2:9700 --token "$TOKEN"
```

## 2. join worker nodes

on each agent node:

```bash
sudo -H "$(command -v yoq)" join 10.0.0.1 --port 7700 --token "$TOKEN"
```

## 3. deploy the manifest

identify the leader with `sudo -H "$(command -v yoq)" cluster status` on the servers. the command below assumes `10.0.0.1:7700` is the leader; substitute its current address. run it from a server or operator host with the api token installed.

```bash
sudo -H env DB_PASSWORD=supersecret "$(command -v yoq)" up --server 10.0.0.1:7700 -f examples/cluster/manifest.toml
```

## 4. verify

```bash
sudo -H "$(command -v yoq)" nodes --server 10.0.0.1:7700
sudo -H "$(command -v yoq)" status --server 10.0.0.1:7700
sudo -H "$(command -v yoq)" metrics --server 10.0.0.1:7700
```

## maintenance

follow the [cluster upgrade procedure](../../docs/install-and-recovery.md#cluster-upgrades) before draining or replacing a node. upgrade every voter before using the new drain transitions. keep a draining agent online until its status is `drained` and it has no running containers.

this example's `pgdata` and `backups` volumes are node-local. automatic drain cannot move that data, so a host running a volume-backed service can remain `drain_blocked`. plan the data move and verify the saved postgres rows after recovery. stateless services need spare placement capacity and a ready replacement before the original stops; see [draining a node](../../docs/cluster-guide.md#draining-a-node).

## notes

- open ports 80 and 443 on the node serving `myapp.example.com` if you want ACME issuance to succeed
- set `DB_PASSWORD` before deploying to override the default database password
- the manifest includes services and an hourly backup cron; deploy it as one app with the remote manifest workflow
