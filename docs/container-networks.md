# local container networks

standalone containers use the default bridge unless `--network` selects a named network or `none`. named networks have their own Linux bridge, IPv4 subnet, and DNS scope. they do not change manifest or cluster networking.

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

network names are DNS labels: 1–63 letters, digits, or hyphens, without a leading or trailing hyphen. `default` and `none` are reserved. the default bridge is selected with `--network default`; `--network none` or `--no-net` disables container networking.

each container selects one network at creation. live connection, disconnection, and multiple network attachments are not supported. created and stopped containers retain their network reference, so `network rm` requires removing those containers first. failed bridge or rule cleanup retains the network definition so removal can be retried.

subnets are private, aligned IPv4 `/24` networks. automatic allocation searches `172.30.0.0/16`; explicit subnets cannot overlap existing named networks, host routes, or the default `10.42.0.0/16` pool. the gateway is `.1`, with container addresses from `.2` through `.254`. ipv6 and other subnet sizes are not supported.

## names and aliases

the container name recorded at creation is its network DNS name. add aliases with repeatable `--network-alias NAME` options. aliases use the same label syntax and require a named network. names and aliases are unique within their network, compared without regard to letter case. different networks can reuse an alias.

only running containers with active attachments resolve. dns returns IPv4 addresses for names in the selected network; it does not search the default service registry or other named networks. unknown short names return NXDOMAIN. external dotted names are forwarded to the host's configured upstream DNS server. local names have no IPv6 answer.

a supervisor serves DNS on the bridge gateway. other supervisors on that network retry ownership if it exits. network references and aliases survive container restarts; container addresses may change.

## published ports

`-p` and `--publish` accept `[HOST_IP:][HOST_PORT:]CONTAINER_PORT[/tcp|udp]`. tcp is the default. host addresses must be IPv4 addresses available on the host. omitting the address publishes on all IPv4 host addresses; `127.0.0.1` limits the mapping to that loopback address.

```sh
yoq run -d -p 127.0.0.1:8080:80 alpine httpd -f
yoq create -p 127.0.0.1::53/udp dns-image
yoq create -p 9000-9002:8000-8002 app-image
```

an omitted or zero host port requests an available port at creation. equal-length host and container ranges expand into individual mappings, with at most 256 published ports per container. ranges must be ascending and nonzero; IPv6 bind addresses are not supported.

`container inspect NAME` shows the assigned mappings in `config.port_maps`; named-network JSON inspection also includes them. assigned ports remain reserved across stops and restarts until the container is removed. a running supervisor holds the host sockets. stopping releases those sockets, so an unrelated host process can occupy a saved port; a later start then fails until that port is free.

## linux host requirements

bridge networking requires Linux network namespaces, veth pairs, IPv4 forwarding, and working `iptables` filter and NAT tables. container startup needs the privileges required by the local runtime; see [local containers](local-containers.md). use the same account and data directory for network and container commands.

named bridges permit same-network traffic and outgoing traffic, with masquerading for egress. forwarding rules isolate them from other local managed bridges. published ports use NAT on the selected bridge. dns binds UDP port 53 on its gateway, so host loopback DNS can coexist. network removal requires enough privilege to delete its bridge and firewall rules.
