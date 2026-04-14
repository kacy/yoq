# rollouts

this guide explains how app rollouts work in yoq today. it covers rollout policy, rollout state, control state, target progress, checkpoints, and recovery.

## where rollout policy lives

rollout policy is part of the service definition in the manifest and is preserved in the canonical app snapshot and release history.

```toml
[service.web.rollout]
strategy = "rolling"
parallelism = 2
delay_between_batches = "5s"
failure_action = "rollback"
health_check_timeout = "20s"
```

local `yoq up` and remote `yoq up --server` both execute from the same stored rollout policy.

## strategies

yoq supports three rollout strategies for service replacement applies:

- `rolling`
  advances targets in batches using `parallelism`
- `canary`
  advances one target first, then continues with the configured `parallelism`
- `blue_green`
  schedules one readiness-gated full batch and cuts over only after the batch is ready

when multiple services are selected together, yoq merges rollout policy conservatively so one release still has one effective execution policy.

## readiness gating

`health_check_timeout` controls rollout readiness gating:

- `0s` disables rollout health gating
- non-zero values wait for target readiness before cutover completes

local behavior:

- readiness comes from the service startup path and local health-check engine

cluster behavior:

- readiness comes from assignment startup
- when a service health check is configured, agent-side service health must also clear before the target is treated as ready

## failure actions

`failure_action` controls what happens when a later batch fails after earlier work has already cut over.

- `pause`
  leaves the rollout blocked for operator action
- `rollback`
  restores earlier cut-over targets when a later batch fails

cluster rollback now restores prior assignments from stored workload snapshots instead of only reporting a failed release.

## rollout states

operator surfaces expose a derived `rollout_state` in addition to release `status`.

current rollout states:

- `pending`
- `starting`
- `rolling`
- `stable`
- `blocked`
- `degraded`
- `failed`
- `rolled_back`

these are exposed in:

- `yoq apps`
- `yoq status --app`
- `yoq history --app`
- `GET /apps`
- `GET /apps/{name}/status`
- `GET /apps/{name}/history`

## control states

active rollouts also carry a `rollout_control_state`:

- `active`
- `paused`
- `cancel_requested`

commands:

```bash
yoq rollout pause --app myapp
yoq rollout resume --app myapp
yoq rollout cancel --app myapp

yoq rollout pause --app myapp --server 10.0.0.1:7700
yoq rollout resume --app myapp --server 10.0.0.1:7700
yoq rollout cancel --app myapp --server 10.0.0.1:7700
```

paused in-progress releases project to `rollout_state = "blocked"`.

## progress and failure reporting

rollout status is structured, not message-only.

app apply/status/history surfaces expose:

- `completed_targets`
- `failed_targets`
- `remaining_targets`
- `failure_details`
- `rollout_targets`

`failure_details` carries structured workload-level causes such as:

- `placement_failed`
- `readiness_timeout`
- `readiness_failed`
- `start_failed`
- `process_failed`
- `image_pull_failed`

`rollout_targets` carries per-target state when available, including terminal outcomes and rollback-driven `rolled_back` targets.

## checkpoints and recovery

active rollouts persist `rollout_checkpoint` data. checkpoints capture enough state to inspect and recover an interrupted rollout.

the checkpoint is exposed in app apply/status/history JSON under:

- top-level `rollout_checkpoint`
- nested `rollout.checkpoint`

checkpoint-aware behavior:

- paused rollouts can be resumed
- target progress is preserved
- already terminal targets are not replayed
- cluster leaders can recover active rollouts after restart or leadership handoff

current implementation note:

- resume is durable and checkpoint-aware
- cluster recovery resumes the same release id in place
- this is still part of the main app-release executor, not a separate detached background job system

## reading operator output

the canonical nested JSON shape is:

- `current_release`
- `previous_successful_release`
- `workloads`
- `training_runtime`
- `rollout`

the nested `rollout` object is the preferred contract for automation. older top-level rollout fields remain for compatibility.

text output also exposes rollout and control state directly:

- `yoq status --app` includes `ROLLOUT` and `CTRL`
- `yoq history --app` includes `ROLLOUT` and `CTRL`
- rollback summaries also show rollout state and control state

## practical operator flow

for a rollout you want to watch closely:

```bash
yoq up --server 10.0.0.1:7700 -f manifest.toml
yoq status --app myapp --server 10.0.0.1:7700
yoq rollout pause --app myapp --server 10.0.0.1:7700
yoq history --app myapp --server 10.0.0.1:7700
yoq rollout resume --app myapp --server 10.0.0.1:7700
```

if the rollout should be abandoned:

```bash
yoq rollout cancel --app myapp --server 10.0.0.1:7700
yoq rollback --app myapp --server 10.0.0.1:7700
```

for local operation, use the same commands without `--server`.
