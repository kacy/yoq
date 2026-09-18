# GCP validation rig

Temporary 5-node GCE rig for validating `yoq` on real cloud hardware.

Topology:
- 3 on-demand CPU servers
- 2 on-demand CPU agents by default
- optional Spot GPU agents if `USE_GPU_AGENTS=true`

What to do:
1. Copy `config.env.example` to `config.env` and set `PROJECT_ID`.
2. Run `./up.sh` to create the VMs and wait for SSH readiness.
3. set `GH_TOKEN` for github release verification, then run `./install.sh` to install `yoq` and its prerequisites on each node.
4. Run `./bootstrap.sh` to form the cluster and join the agents.
5. Run `./validate.sh` to check networking, containers, and optional GPU smoke.
6. Run `./down.sh` when finished.

Notes:
- Artifacts go under `infra/gcp/artifacts/`.
- State lives under `infra/gcp/.state/`.
- CPU-only mode is the default; set `USE_GPU_AGENTS=true` if you want GPU workers.
- `install.sh` installs `yoq` on each node from the release installer URL so the VM picks the correct architecture automatically.
- nodes install github cli from its [official apt repository](https://github.com/cli/cli/blob/trunk/docs/install_linux.md). the installer sends `GH_TOKEN` over ssh stdin for attestation verification; it does not write the token to a remote file. gcloud manages ssh host verification.
- The CPU image family defaults to `ubuntu-2204-lts`; older configs using `ubuntu-2204-lts-amd64` are translated automatically.
- GPU mode requires non-zero `GPUS_ALL_REGIONS` quota.
- `down.sh` uses `infra/gcp/.state/current` when available and exits cleanly if no rig state exists.
- record the installed version and executable hash on every node. the release installer does not deploy the checkout, and `YOQ_BINARY_PATH` selects only the local validation cli.
- `validate.sh` covers its listed smoke checks. drain handoffs, leader restart during a handoff, and large-command follower catch-up need the [additional reliability acceptance checks](../../docs/gcp-cluster-validation.md#additional-reliability-acceptance).
- read the [upgrade requirements](../../docs/install-and-recovery.md#cluster-upgrades) before reusing a rig with existing state. complete older apply and training commands before switching local lock protocols.
- full usage details are in the [gcp validation guide](../../docs/gcp-cluster-validation.md).
