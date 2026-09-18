# local container healthchecks

Standalone containers run the healthcheck saved from their image configuration.
`CMD` executes its argument list directly. `CMD-SHELL` runs `/bin/sh -c` inside
the container. `NONE` disables checks. Each check uses the container's saved
environment, working directory, namespaces, and filesystem.

Health starts as `starting`. A successful check changes it to `healthy` and resets
the failure count. Three consecutive failures change it to `unhealthy` by default;
the image's `Retries` setting can change that threshold. Failures during
`StartPeriod` do not count until the first successful check. Health status does
not itself restart a container.

The default interval and timeout are both 30 seconds. During the initial grace
period, checks use `StartInterval`, which defaults to 5 seconds. The next interval
starts after the previous check finishes. Nonzero durations must be between
1 millisecond and 24 hours. Retries must be between 1 and 1,000,000; zero selects
the default. Missing values also select defaults.

Checks pause while the container is frozen. Freezing a container cancels any
check already in progress without counting a failure. Stop, restart, and timeout
terminate the helper and its descendants. Each check has its own cgroup with the
container's configured resource limits; those limits bound the check separately
from the workload. Recovery removes abandoned check cgroups before another run.

The saved health record contains the status, failing streak, last exit code, and
completion timestamp. Timeout records exit code 124; a runner failure records
125. Check output is discarded. Results are accepted only while the matching
container PID and run generation are current, so a delayed result cannot replace
the status of a newer run.
