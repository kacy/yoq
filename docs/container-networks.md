# local container networks

Standalone containers use the default bridge unless `--network` selects a named network or `none`. Named networks have their own Linux bridge, IPv4 subnet, and DNS scope. They do not change manifest or cluster networking.

```sh
yoq network create app-net
yoq network create --subnet 192.168.120.0/24 workers
yoq network ls --json
yoq run -d --name database --network app-net --network-alias db alpine sleep 300
yoq network inspect --json app-net
yoq stop database
yoq rm database
yoq network rm app-net
```

## commands and lifecycle

| command | behavior |
| --- | --- |
| `network create [--subnet CIDR] NAME` | saves a network definition; creates the bridge when its first container starts |
| `network ls [--json]` | lists named networks and reference counts |
| `network inspect [--json] NAME` | shows the bridge, subnet, gateway, and container references; JSON includes aliases and published ports |
| `network rm NAME` | removes an unused network and its bridge rules |

Network names are DNS labels: 1–63 letters, digits, or hyphens, without a leading or trailing hyphen. `default` and `none` are reserved. The default bridge is selected with `--network default`; `--network none` or `--no-net` disables container networking.

Each container selects one network at creation. Live connection, disconnection, and multiple network attachments are not supported. Created and stopped containers retain their network reference, so `network rm` requires removing those containers first. Failed bridge or rule cleanup retains the network definition so removal can be retried.

Subnets are private, aligned IPv4 `/24` networks. Automatic allocation searches `172.30.0.0/16`; explicit subnets cannot overlap existing named networks, host routes, or the default `10.42.0.0/16` pool. The gateway is `.1`, with container addresses from `.2` through `.254`. IPv6 and other subnet sizes are not supported.

## names and aliases

The container name recorded at creation is its network DNS name. Add aliases with repeatable `--network-alias NAME` options. Aliases use the same label syntax and require a named network. Names and aliases are unique within their network, compared without regard to letter case. Different networks can reuse an alias.

Only running containers with active attachments resolve. DNS returns IPv4 addresses for names in the selected network; it does not search the default service registry or other named networks. Unknown short names return NXDOMAIN. External dotted names are forwarded to the host's configured upstream DNS server. Local names have no IPv6 answer.

A supervisor serves DNS on the bridge gateway. Other supervisors on that network retry ownership if it exits. Network references and aliases survive container restarts; container addresses may change.

## published ports

`-p` and `--publish` accept `[HOST_IP:][HOST_PORT:]CONTAINER_PORT[/tcp|udp]`. TCP is the default. Host addresses must be IPv4 addresses available on the host. Omitting the address publishes on all IPv4 host addresses; `127.0.0.1` limits the mapping to that loopback address.

```sh
yoq run -d -p 127.0.0.1:8080:80 alpine httpd -f
yoq create -p 127.0.0.1::53/udp dns-image
yoq create -p 9000-9002:8000-8002 app-image
```

An omitted or zero host port requests an available port at creation. Equal-length host and container ranges expand into individual mappings, with at most 256 published ports per container. Ranges must be ascending and nonzero; IPv6 bind addresses are not supported.

`container inspect NAME` shows the assigned mappings in `config.port_maps`; named-network JSON inspection also includes them. Assigned ports remain reserved across stops and restarts until the container is removed. A running supervisor holds the host sockets. Stopping releases those sockets, so an unrelated host process can occupy a saved port; a later start then fails until that port is free.

## linux host requirements

Bridge networking requires Linux network namespaces, veth pairs, IPv4 forwarding, and working `iptables` filter and NAT tables. Container startup needs the privileges required by the local runtime; see [local containers](local-containers.md). Use the same account and data directory for network and container commands.

Named bridges permit same-network traffic and outgoing traffic, with masquerading for egress. Forwarding rules isolate them from other local managed bridges. Published ports use NAT on the selected bridge. DNS binds UDP port 53 on its gateway, so host loopback DNS can coexist. Network removal requires enough privilege to delete its bridge and firewall rules.
