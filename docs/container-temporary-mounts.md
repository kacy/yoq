# cpu sets and temporary mounts

`yoq run` and `yoq create` accept CPU affinity and temporary filesystem settings.
The settings are saved with the container and applied again on start or restart.

```sh
yoq run --cpuset-cpus 0-2,4 --shm-size 128m \
  --tmpfs /cache:size=32m,mode=750,noexec image command
```

`--cpuset-cpus` accepts CPU numbers and inclusive ranges separated by commas.
Numbers may appear in any order. Every requested CPU must be available to the
container's cgroup; unavailable CPUs cause startup to fail. The runtime enables
the cgroup v2 cpuset controller when needed. Omitting the option inherits the
parent cgroup's available CPUs. CPU lists are limited to 512 bytes.

`--shm-size` sets the size of `/dev/shm`, which defaults to 64 MiB. `/tmp` keeps its
existing 64 MiB default. Sizes accept bytes or the `k`, `m`, and `g` suffixes and
must be positive. These limits cap filesystem capacity; they do not reserve RAM.
Memory charged to these filesystems also counts toward the container's memory
limit.

`--tmpfs /path[:options]` adds an empty temporary filesystem. Repeat the option
for more paths, up to 256. Its defaults are 64 MiB, mode `1777`, read-write,
executable, `nosuid`, and `nodev`. Supported comma-separated options are:

- `size=SIZE` and `mode=OCTAL`
- `ro` or `rw`
- `exec` or `noexec`
- `suid` or `nosuid`
- `dev` or `nodev`

Targets must be absolute paths without `.` or `..` components. The root,
`/proc`, `/sys`, `/dev`, and `/dev/pts` are reserved. An explicit tmpfs overrides
an image's `VOLUME` declaration for the same target. Specifying both a bind or
volume mount and a tmpfs at the same target is an error. Parent mounts are applied
before their children, even when options appear in another order. a read-only
tmpfs cannot contain a nested mount: its empty filesystem cannot create the child
mountpoint.

Temporary filesystem contents disappear when the container stops. Starting the
same container creates fresh temporary filesystems with the saved settings.

`--restart on-failure:N` saves a positive retry limit for failed runs. Other
restart policies do not accept a retry count. `on-failure` without a count keeps
its unlimited retry behavior.
