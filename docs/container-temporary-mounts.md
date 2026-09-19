# cpu sets and temporary mounts

`yoq run` and `yoq create` accept CPU affinity and temporary filesystem settings.
the settings are saved with the container and applied again on start or restart.

```sh
yoq run --cpuset-cpus 0-2,4 --shm-size 128m \
  --tmpfs /cache:size=32m,mode=750,noexec image command
```

`--cpuset-cpus` accepts CPU numbers and inclusive ranges separated by commas.
numbers may appear in any order. every requested CPU must be available to the
container's cgroup; unavailable CPUs cause startup to fail. the runtime enables
the cgroup v2 cpuset controller when needed. omitting the option inherits the
parent cgroup's available CPUs. cpu lists are limited to 512 bytes.

`--shm-size` sets the size of `/dev/shm`, which defaults to 64 MiB. `/tmp` keeps its
existing 64 MiB default. sizes accept bytes or the `k`, `m`, and `g` suffixes and
must be positive. these limits cap filesystem capacity; they do not reserve RAM.
memory charged to these filesystems also counts toward the container's memory
limit.

`--tmpfs /path[:options]` adds an empty temporary filesystem. repeat the option
for more paths, up to 256. its defaults are 64 MiB, mode `1777`, read-write,
executable, `nosuid`, and `nodev`. supported comma-separated options are:

- `size=SIZE` and `mode=OCTAL`
- `ro` or `rw`
- `exec` or `noexec`
- `suid` or `nosuid`
- `dev` or `nodev`

targets must be absolute paths without `.` or `..` components. the root,
`/proc`, `/sys`, `/dev`, and `/dev/pts` are reserved. an explicit tmpfs overrides
an image's `VOLUME` declaration for the same target. specifying both a bind or
volume mount and a tmpfs at the same target is an error. parent mounts are applied
before their children, even when options appear in another order. a read-only
tmpfs cannot contain a nested mount: its empty filesystem cannot create the child
mountpoint.

temporary filesystem contents disappear when the container stops. starting the
same container creates fresh temporary filesystems with the saved settings.

`--restart on-failure:N` saves a positive retry limit for failed runs. other
restart policies do not accept a retry count. `on-failure` without a count keeps
its unlimited retry behavior.
