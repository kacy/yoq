# local containers

this guide describes the current source tree, reviewed 2026-09-19. published 0.2.1 binaries do not include all of these commands. the [compatibility table](container-compatibility.md) records the remaining gaps.

standalone containers use `run`, `create`, and `container` commands. manifest services use `up` and `down`, with app releases and dependency ordering. both use the same runtime, but their supervisors own different lifecycles.

local execution needs linux 6.1+, cgroups v2, and root privileges. use the same home directory for every command so they see the same images, volumes, and container records. the examples use `sudo -H` and resolve the installed binary before sudo changes the path.

## build and run locally

save this as `Dockerfile` in an empty directory:

```dockerfile
FROM alpine:3.22
WORKDIR /work
ENV GREETING=hello
CMD ["sh", "-c", "printf '%s\\n' \"$GREETING\""]
```

```bash
sudo -H "$(command -v yoq)" build -t local-demo:latest .
sudo -H "$(command -v yoq)" run --pull never --name demo local-demo:latest
sudo -H "$(command -v yoq)" container inspect demo
sudo -H "$(command -v yoq)" ps -a
sudo -H "$(command -v yoq)" rm demo
```

the first build needs the base image. after that, `--pull never` runs the local tag without contacting a registry. the default, `--pull missing`, uses a local match before pulling. `--pull always` resolves through the registry even when a local tag exists. each container saves the resolved image digest and effective configuration; moving a tag does not change an existing container.

`yoq inspect IMAGE` still inspects an image. use `yoq container inspect NAME` for the container's saved process settings, mounts, ports, state, and health status. `ps` shows running, paused, and restarting containers; `ps -a` includes stopped and created containers. `ps -q` prints ids. filters accept `status=VALUE`, `name=SUBSTRING`, and `id=PREFIX`; multiple filters must all match.

## keep a container between runs

```bash
sudo -H "$(command -v yoq)" create --name worker local-demo:latest sh -c 'while :; do sleep 1; done'
sudo -H "$(command -v yoq)" start worker
sudo -H "$(command -v yoq)" exec worker sh -c 'printf saved > /work/note'
sudo -H "$(command -v yoq)" stop worker
sudo -H "$(command -v yoq)" start worker
sudo -H "$(command -v yoq)" exec worker cat /work/note
sudo -H "$(command -v yoq)" stop worker
sudo -H "$(command -v yoq)" rm worker
```

stopping a container releases its process resources and network endpoint. its name, configuration, volume references, and writable image layer remain. starting or restarting it uses that same layer. removal deletes the layer and logs. a rootfs path supplied directly to `run` remains a host-owned directory.

names are unique across stopped and running containers. `--hostname` sets the process hostname independently. `yoq rename ID NEW-NAME` changes the lookup name without changing that hostname or an existing network alias. older records with duplicate hostnames must be addressed by id and renamed before lookup by name becomes unambiguous.

`wait NAME` prints the process exit code. `kill --signal TERM NAME` sends a signal without changing restart policy. `stop NAME` records a stop request before signaling, so an automatic restart cannot undo it. `--stop-signal` overrides the image's stop signal; `--stop-timeout` sets the grace period in seconds before forced termination. new containers default to 10 seconds.

restart policies are `no`, `always`, `on-failure`, and `unless-stopped`. automatic restarts back off from one second to 30 seconds. `on-failure:N` permits at most N automatic retries after an initial failure; inspect reports the restart count. an explicit stop suppresses them for the current host session. `--rm` removes a container and its anonymous volumes after its final exit; it cannot be combined with a restart policy. named volumes remain.

cleanup failures leave a `cleanup_failed` record. retry `stop` or `rm` after correcting the reported failure. a new start cannot overwrite resources still awaiting cleanup.

## process settings and sessions

`--entrypoint` replaces the image entrypoint and clears the inherited command. arguments after the image become its command arguments. `--workdir`/`-w` and `--user`/`-u` override image settings. exec uses the saved environment, working directory, user, and executable search path.

use `-e KEY=value` to set a value or `-e KEY` to copy it from the invoking environment. an unset host variable removes an inherited image value. `--env-file PATH` reads literal `KEY=value` lines, blank lines, and comments beginning with `#`. it accepts windows line endings. it does not expand shell expressions or strip quotes. explicit `-e` values take precedence over env-file values, regardless of flag order.

```bash
sudo -H "$(command -v yoq)" run -dit --name shell local-demo:latest sh
sudo -H "$(command -v yoq)" attach shell
sudo -H "$(command -v yoq)" exec -it shell sh
```

`-i` keeps stdin available; `-t` allocates a terminal. terminal sessions merge stdout and stderr, handle terminal size changes, and restore the caller's terminal on exit. press ctrl-p, then ctrl-q to detach from an attached terminal without stopping the process. these bytes remain ordinary input in a pipe. `attach --no-stdin` observes output without claiming stdin. one client owns stdin; up to eight clients can observe a session.

without `-t`, foreground output preserves raw bytes and separates stderr from stdout. a foreground command returns its attempt's exit status even if the restart policy starts another attempt in the background. terminal detach returns zero. a slow attachment is disconnected instead of blocking the container's log capture; use `logs` for stored output.

`logs NAME --tail 0` prints no history. `logs NAME --tail 20 -f` prints the requested tail, then follows container identity through automatic restarts. log records include stream and timestamp metadata; they are separate from raw attachment output. each log generation is bounded to 50 mib with one rotated file retained. the command reads the current generation, not a concatenation of both files.

## storage

structured bind mounts are writable by default:

```bash
sudo -H "$(command -v yoq)" run --rm \
  --mount type=bind,src="$PWD",dst=/project,readonly \
  local-demo:latest ls /project
```

legacy `-v /host:/container` and colon-form `--mount` keep yoq's read-only default; specify `:rw` for writes. colon-form `--mount` emits a deprecation warning. saved configurations retain their effective mount modes during upgrades.

```bash
sudo -H "$(command -v yoq)" volume create notes
sudo -H "$(command -v yoq)" run --rm -v notes:/data local-demo:latest sh -c 'printf saved > /data/note'
sudo -H "$(command -v yoq)" run --rm -v notes:/data local-demo:latest cat /data/note
sudo -H "$(command -v yoq)" volume inspect notes
sudo -H "$(command -v yoq)" volume rm notes
```

named and anonymous volumes are writable by default. `--mount type=volume,dst=/data` creates an anonymous volume. an empty volume is initialized from the image's directory on its first start, unless `volume-nocopy` is set. image `VOLUME` declarations create anonymous volumes unless a command-line mount overrides that target. nonempty volumes are never overwritten by initialization.

stopped containers retain volume references, so `volume rm` rejects a referenced volume. ordinary `rm` preserves volumes. `rm -v` additionally removes anonymous volumes; named volumes require `volume rm`. use [cp and diff](container-filesystems.md) to copy files or inspect changes in an image container's writable layer.

## ports and host recovery

`-p 127.0.0.1:8080:80` publishes tcp on a specific ipv4 address. add `/udp` for udp. `-p 80` or `-p 0:80` assigns a host port; read the assignment with `container inspect`. reservations remain stable across stop/start and are released on removal. a running container holds host sockets for its published ports, and startup fails if another process already owns them. `--no-net` disables container networking and cannot be combined with published ports. matching ranges such as `8000-8003:80-83/tcp` expand to individual mappings, with at most 256 mappings per container.

use `network create NAME`, then `run --network NAME`, for a named ipv4 bridge. `--network-alias` adds names visible within that network. stopped containers retain references, so remove them before `network rm`. see [local networks](container-networks.md) for subnet allocation, dns scope, and cleanup.

standalone supervisors are independent processes; there is no required central daemon. after a host reboot, `yoq container recover` retries `always` containers and `unless-stopped` containers whose saved desired state is running. it does not restart `no` or `on-failure` containers. recovery is a boot action, not a periodic reconciliation command: periodically invoking it would undo a manual stop under `always`.

an optional boot unit is provided at `packaging/yoq-containers.service`. set its binary path and `HOME` to match the installation and state directory before installing it. it is not enabled automatically. this unit handles standalone containers; it does not replace manifest or cluster recovery.

see [temporary mounts and cpu affinity](container-temporary-mounts.md), [resource controls](container-resources.md), [health checks](container-healthchecks.md), and [image archives](image-archives.md) for their exact behavior and limits.
