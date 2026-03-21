# GCP validation rig

Temporary 5-node GCE rig for validating `yoq` on real cloud hardware.

Topology:
- 3 on-demand CPU servers
- 2 on-demand CPU agents by default
- optional Spot GPU agents if `USE_GPU_AGENTS=true`

What to do:
1. Copy `config.env.example` to `config.env` and set `PROJECT_ID`.
2. Run `./up.sh` to create the VMs and wait for SSH readiness.
3. Run `./install.sh` to copy `yoq` onto each node and verify prerequisites.
4. Run `./bootstrap.sh` to form the cluster and join the agents.
5. Run `./validate.sh` to check networking, containers, and optional GPU smoke.
6. Run `./down.sh` when finished.

Notes:
- Artifacts go under `infra/gcp/artifacts/`.
- State lives under `infra/gcp/.state/`.
- CPU-only mode is the default; set `USE_GPU_AGENTS=true` if you want GPU workers.
- `install.sh` installs `yoq` on each node from the release installer URL so the VM picks the correct architecture automatically.
- The CPU image family defaults to `ubuntu-2204-lts`; older configs using `ubuntu-2204-lts-amd64` are translated automatically.
- GPU mode requires non-zero `GPUS_ALL_REGIONS` quota.
- `down.sh` uses `infra/gcp/.state/current` when available and exits cleanly if no rig state exists.
- Full usage details are in `docs/gcp-cluster-validation.md`.
