# local container compatibility

reviewed 2026-09-19 against the current source tree. this table describes native yoq behavior, not a claim that arbitrary docker clients or workloads are interchangeable. use the installed binary's help when running a published release.

| area | status | behavior and limits |
| --- | --- | --- |
| image resolution | implemented | local-first run; missing/always/never pull policies; saved resolved digest |
| persistent containers | implemented | create/start/stop/restart/remove retain the writable layer until removal |
| ownership | implemented | serialized cli/api stop/remove; durable stop requests; stale supervisors cannot start a new attempt |
| identity | implemented | unique standalone names, separate hostname, rename, explicit duplicate legacy-name errors; full ids or names, without short-id lookup |
| inspection | implemented | container inspect shows saved config/state/health; ps supports all/quiet/json and status/name/id filters |
| process overrides | implemented | entrypoint, command, env/env-file, workdir, user, hostname, stop signal/timeout |
| sessions | implemented | stdin pipes, raw stdout/stderr, terminals, resize, detach, attach; eight clients and one stdin owner |
| restart | partial | no/always/on-failure[:N]/unless-stopped, bounded backoff, optional boot recovery; host recovery must be invoked after reboot |
| volumes | implemented | named/anonymous local volumes, image VOLUME initialization, nocopy, reference tracking, explicit anonymous cleanup |
| bind mounts | partial | structured mounts default writable; legacy colon mounts retain yoq's read-only default |
| ports | partial | tcp/udp, ipv4 bind address, stable ephemeral host assignments and equal-length ranges; no ipv6 publishing |
| named networks | partial | one named ipv4 bridge attachment, scoped names/aliases, references across stop/start; no live connect/disconnect or multiple attachments |
| health | implemented | image and run overrides, grace/retries/timeouts, status reporting, cancellation and orphan cleanup; output discarded; unhealthy does not trigger restart |
| resources | partial | hard/soft memory, pids, cpu quota/weight, creation-time cpu sets, explicit unlimited settings, live limit updates, pause/unpause; stats is a snapshot with cumulative cpu time |
| temporary mounts | implemented | configurable /dev/shm and typed tmpfs mounts; settings fixed at creation, contents discarded on stop |
| filesystem tools | partial | cp and diff work on running and stopped image containers; cp excludes archives, ownership/xattrs, device nodes and hardlink topology; mounted volumes are outside diff |
| image metadata | implemented | command arrays, shell forms, user/workdir/env, labels, exposed ports, volumes, stop signal, healthcheck, target architecture |
| image archives | partial | tag and uncompressed single-platform oci image-layout save/load; no legacy docker archive format, nested multi-platform indexes, or rootfs import/export |
| logs | partial | bounded storage, exact tail zero, streaming reads, follow through automatic restarts; history reads the current log generation |
| external tooling | deferred | docker engine api, compose input, desktop integrations, and broad buildkit compatibility need separate interface designs |

## upgrade behavior

saved run configurations are versioned. this source reads versions 1–7 and writes
version 7. existing user settings and mount modes are retained. versions 1 and 2,
which did not store a stop timeout, keep their five-second default; later versions
retain the saved timeout. new containers default to ten seconds. existing
writable-layer contents cannot be recovered if an older supervisor deleted them.

older configurations without the new fields inherit the parent CPU set, use
64 mib for `/dev/shm`, have no additional tmpfs mounts, and have no retry-count
limit. `/tmp` keeps its 64 mib default. `/dev/shm` is now mounted separately when
the container next starts. volume and network references are retained by stopped
containers, so remove the referring containers before removing those resources.

stop running standalone containers before replacing the binary. a supervisor already in memory keeps its old behavior until it exits. start the saved containers with the new binary after the upgrade. do not run old and new binaries against the same state directory; new saved-config versions cannot be read by older binaries.

old duplicate names are not silently assigned to one owner. list records with `ps -a`, address them by id, and use `rename ID NAME`. renaming changes the lookup name; it preserves the configured hostname and network aliases.

`ps` now shows active containers by default. scripts that need stopped records must use `ps -a`. stdout from a foreground run contains only process output; the container id is printed by detached run and create. structured bind mounts default to writable; the old colon syntax stays read-only unless `rw` is explicit. use explicit modes in scripts.

## command differences

run/create options precede the image. only `-it` and `-ti` are supported combined
session flags; use `-d -it` rather than `-dit`. boolean switches reject assigned
values such as `--rm=false`. exec accepts session flags and uses saved process
settings; it does not accept per-exec environment, user, or workdir overrides.
`rm` requires a stopped container and has no force option.

`container inspect` always emits JSON. custom formatting templates are not
supported. `volume` commands emit text; `network ls` and `network inspect` offer
`--json`. CPU sets, shared-memory capacity, and tmpfs mounts cannot be changed with
`update`; recreate the container to change those settings.

## separate follow-up designs

live network attachment needs endpoint updates, resolver changes, route selection, and rollback across multiple attachments. rootfs import/export needs a separate archive contract because it does not preserve image history and metadata the way image save/load does.

a docker engine adapter needs an agreed client set and endpoint contract. compose support needs explicit rules for translating services, dependencies, volumes, and networks into yoq's app model. neither follows automatically from similar command names. these remain separate proposals rather than advertised compatibility.
