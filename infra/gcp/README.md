# GCP validation rig

Temporary 5-node GCE rig for validating `yoq` on real cloud hardware.

Topology:
- 3 on-demand CPU servers
- 2 Spot GPU agents

What to do:
1. Copy `config.env.example` to `config.env` and set `PROJECT_ID`.
2. Run `./up.sh` to create the VMs and wait for SSH readiness.
3. Run `./install.sh` to copy `yoq` onto each node and verify prerequisites.
4. Run `./bootstrap.sh` to form the cluster and join the GPU agents.
5. Run `./validate.sh` to check networking, containers, GPU passthrough, and training smoke.
6. Run `./down.sh` when finished.

Notes:
- Artifacts go under `infra/gcp/artifacts/`.
- State lives under `infra/gcp/.state/`.
- The CPU image family defaults to `ubuntu-2204-lts`; older configs using `ubuntu-2204-lts-amd64` are translated automatically.
- The project must have non-zero `GPUS_ALL_REGIONS` quota before `up.sh` can create the GPU agents.
- Full usage details are in `docs/gcp-cluster-validation.md`.
