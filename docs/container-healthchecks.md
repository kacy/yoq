# local container healthchecks

standalone containers run the healthcheck saved from their image configuration.
`CMD` executes its argument list directly. `CMD-SHELL` runs `/bin/sh -c` inside
the container. `NONE` disables checks. each check uses the container's saved
environment, working directory, user, namespaces, and filesystem.

health starts as `starting`. a successful check changes it to `healthy` and resets
the failure count. three consecutive failures change it to `unhealthy` by default;
the image's `Retries` setting can change that threshold. failures during
`StartPeriod` do not count until the first successful check. health status does
not itself restart a container.

the default interval and timeout are both 30 seconds. during the initial grace
period, checks use `StartInterval`, which defaults to 5 seconds. the next interval
starts after the previous check finishes. nonzero durations must be between
1 millisecond and 24 hours. retries must be between 1 and 1,000,000; zero selects
the default. missing values also select defaults.

checks pause while the container is frozen. freezing a container cancels any
check already in progress without counting a failure. stop, restart, and timeout
terminate the helper and its descendants. each check has its own cgroup with the
container's configured resource limits; those limits bound the check separately
from the workload. recovery removes abandoned check cgroups before another run.

the saved health record contains the status, failing streak, last exit code, and
completion timestamp. timeout records exit code 124; a runner failure records
125. check output is discarded. results are accepted only while the matching
container PID and run generation are current, so a delayed result cannot replace
the status of a newer run.

`container inspect NAME` includes the health record. `ps --json` also includes it.
use `--no-healthcheck` to disable an image check, or `--health-cmd COMMAND` to set
a shell command. timing overrides are `--health-interval`, `--health-timeout`,
`--health-start-period`, and `--health-start-interval`; values accept units such
as `500ms`, `30s`, or `1m30s`. `--health-retries` sets the failure threshold.
a disabled check cannot be combined with overrides, and timing options require
an image or command-line check to apply to.
