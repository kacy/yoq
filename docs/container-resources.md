# container resources

these commands inspect and change standalone containers by name or full id.

```sh
yoq top web
yoq stats web --json
yoq pause web
yoq unpause web
yoq update web --memory 1g --cpus 2 --pids 1024
yoq update web --memory unlimited --cpus unlimited --pids unlimited
yoq update web --restart on-failure:3
```

`top` lists host process ids, parent ids, process states, and commands from the
container's cgroup. `stats` returns one snapshot. cpu time is cumulative
microseconds; memory values are bytes. both commands accept `--json`. stats json
also includes I/O counters, pressure metrics, and actual controller limits.
missing metrics are `null`; a raw limit of `max` means unlimited.

`pause` freezes the cgroup and waits for the kernel to report completion.
`unpause` waits for it to thaw. the process keeps its memory and writable
filesystem while paused. see the kernel's
[cgroup freezer documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html#core-interface-files)
for its behavior.

`update` accepts `--memory`, `--memory-high`, `--pids`, `--cpu-weight`, `--cpus`,
and `--restart`. omitted settings keep their saved values. memory, pid, and cpu
quota options accept `unlimited`. cpu weight accepts 1 through 10,000.

restart policies are `no`, `always`, `on-failure`, and `unless-stopped`.
`on-failure:N` limits automatic retries after the initial attempt; plain
`on-failure` clears that limit. automatic removal cannot be combined with a
restart policy.

resource changes apply immediately to a running or paused container and are
saved for later starts. updating a stopped container changes its saved
configuration. if a controller write or config save fails, the command tries to
restore the kernel values it read before the update. `PartialUpdate` means
restoration also failed; inspect `stats --json` before retrying. restoring a
limit cannot undo process exits or memory reclamation caused by the new limit.

cpu affinity (`--cpuset-cpus`), shared-memory size (`--shm-size`), and tmpfs mounts
are creation options; `update` does not change them. see
[cpu sets and temporary mounts](container-temporary-mounts.md).
