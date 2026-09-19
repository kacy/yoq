# container resources

these commands inspect and change standalone containers by name or full ID.

```sh
yoq top web
yoq stats web --json
yoq pause web
yoq unpause web
yoq update web --memory 1g --cpus 2 --pids 1024
yoq update web --memory unlimited --cpus unlimited --pids unlimited
yoq update web --restart on-failure
```

`top` lists host process IDs, parent IDs, process states, and commands from the container's cgroup. `stats` prints one snapshot. CPU time is cumulative microseconds, and memory values are bytes. Both accept `--json`; the stats JSON includes I/O counters, pressure metrics, and the actual controller limit values. Missing metrics are `null`; a raw limit value of `max` means unlimited.

`pause` freezes the cgroup and waits for the kernel to report completion. `unpause` waits for it to thaw. The process keeps its memory and writable filesystem while paused. See the kernel's [cgroup freezer documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html#core-interface-files) for its behavior.

`update` accepts `--memory`, `--memory-high`, `--pids`, `--cpu-weight`, `--cpus`, and `--restart`. Omitted settings keep their saved values. Memory, PID, and CPU quota options accept `unlimited`. CPU weight accepts 1 through 10,000. Restart policies are `no`, `always`, `on-failure`, and `unless-stopped`; automatic removal cannot be combined with a restart policy.

resource changes apply immediately to a running or paused container and are saved for later starts. Updates to a stopped container change its saved configuration. If a controller write or config save fails, the command tries to restore the actual kernel values it read before the update. A `PartialUpdate` error means restoration also failed; inspect `stats --json` before retrying. Restoring a resource limit cannot undo process exits or reclamation caused while the new limit was active.
