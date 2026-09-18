# training lifecycle

`yoq train start <name>` starts every local rank before waiting for completion. a job accepts 1–4,096 ranks, subject to available devices and placement capacity. each rank receives one leased gpu, its own network namespace, and the configured command, environment, working directory and volumes. ranks connect to rank zero through the local bridge. `LOCAL_RANK` is zero inside each container because it sees one selected device.

local pause and stop persist the control request before terminating ranks. the running controller checks that request while starting and polling the group. if one rank fails, the controller stops its peers before retrying. restarting a controller removes its stale local ranks before leasing devices again. rank ownership is saved before each container starts; names alone never establish ownership. ranks created before this ownership record was introduced need an explicit `yoq stop <container-id>` before restarting the job.

with `--server host:port`, training commands use the app's committed training definition. start, pause, stop, resume and scale update the replicated job and its assignments together. resume and scale keep the job id; a new start requires the previous run to be stopped, completed or failed. a job stays `scheduling` until its ranks run. the leader reconciles rank results after startup and elections, marks successful groups `completed`, and retries failed groups up to `max_restarts` when `auto_restart` is enabled.

cluster rank zero receives an owned rendezvous port. different gangs reserve different ports, including replicated service gangs. the agent keeps the claim until the rank stops; if publication fails, the agent stops the rank and reports an assignment failure.

checkpoint paths are container paths. mount a writable volume at that path so checkpoints survive replacement. on resume, each agent scans the corresponding host mount and passes the newest step directory as `YOQ_RESUME_FROM`, expressed inside the container. cross-agent recovery requires storage visible to every eligible agent, such as a shared filesystem. the training process writes checkpoints; yoq does not create framework snapshots.

`training.<name>.data` is rejected because automatic dataset preparation and sharding are not implemented. prepare data in the job command and mount it as a volume. nonzero `training.<name>.fault_tolerance.spare_ranks` is also rejected. the default of zero remains supported; failures restart the whole group within the configured retry limit.

upgrade agents before submitting assignments that use these execution fields. older agents do not understand the expanded assignment specification.
