# installation, upgrades, and recovery

use a disposable linux 6.1+ machine for the first run. the host needs cgroups v2, iproute2, iptables, curl, python3, tar, and sha256sum. install github cli with `gh attestation verify` support using its [linux installation instructions](https://github.com/cli/cli/blob/trunk/docs/install_linux.md). wireguard-tools is needed for a cluster; gpu workloads also need the host driver.

## install and check a release

run the installer as your login user. authenticate github cli first; the installer verifies the release's publisher attestations before installing the binary:

```bash
gh auth login --hostname github.com
curl --proto '=https' --proto-redir '=https' -fsSL https://yoq.dev/install -o /tmp/install-yoq-release.sh
sh /tmp/install-yoq-release.sh
rm /tmp/install-yoq-release.sh
yoq version
sudo -H "$(command -v yoq)" doctor
```

`GH_TOKEN` is also accepted by github cli in unattended environments. keep credentials out of command arguments and shell tracing. the [gcp scripts](../infra/gcp/README.md) pass the token over ssh standard input to the remote installer.

the examples resolve the executable in your login shell because a user installation in `~/.local/bin` may be absent from sudo's search path. use `sudo -H` consistently for local runtime commands so they share root's state directory. follow the [golden path](golden-path.md) to validate manifests, start an application, and query the authenticated api. `doctor` checks prerequisites; it does not prove that every kernel capability or application works.

## back up a local installation

create a private backup directory and save the local database:

```bash
sudo install -d -m 0700 /var/backups/yoq
sudo -H "$(command -v yoq)" backup --output /var/backups/yoq/before-upgrade.yoqbackup
sudo -H "$(command -v yoq)" restore --verify /var/backups/yoq/before-upgrade.yoqbackup
```

backups are encrypted and authenticated by default. retain a protected copy of `/root/.local/share/yoq/secrets.key` separately from the backup; the database archive does not include that key. retain the api token if existing clients must keep access after host recovery. volume data, object bytes, image caches, manifests outside the database, and other filesystem state need their own backup policy.

scheduled `[backup]` jobs keep seven backups by default. `keep_count`, `max_age`, and `max_bytes` control pruning; the newest backup is protected. a retention policy is not a substitute for a restore drill.

## upgrade and restore locally

record `yoq version`, save a database backup and the current executable, and stop the application supervisors and api server using the mechanism that started them. install the verified replacement release, then run `sudo -H "$(command -v yoq)" doctor` and the application's normal startup command. inspect `sudo -H "$(command -v yoq)" status --app <name>`, health checks, and the application's actual request path.

if recovery is needed, stop every process using the local database before restoring:

```bash
sudo -H "$(command -v yoq)" restore --verify /var/backups/yoq/before-upgrade.yoqbackup
sudo -H "$(command -v yoq)" restore /var/backups/yoq/before-upgrade.yoqbackup
```

restart with a binary compatible with the restored database, then repeat the status and application checks. app rollback re-applies a saved release; database restore replaces local state. the legacy service rollback command only prints saved configuration.

## cluster upgrades

`yoq backup` covers the local `yoq.db`; it is not a coordinated backup of the raft log, replicated `cluster/state.db`, agent state, or application volumes. do not restore that archive over cluster state or copy one live sqlite file while omitting its wal.

run `sudo -H "$(command -v yoq)" upgrade preflight --server <server-ip>:7700` before maintenance. keep the original fixed voter set. for an ordinary compatible upgrade, drain agents and replace servers while retaining quorum. this validation change requires a coordinated upgrade of all voters before accepting writes: follow [replicated command recovery](cluster-guide.md#upgrading-replicated-command-validation), including its checks for unsupported historical commands. do not assume that an old snapshot is consistent merely because it opens successfully.

## offline cluster recovery

`yoq cluster backup` captures one stopped voter, including its raft databases, selected snapshot, api token, join token, and available local encryption key. stop every voter and agent before taking the first bundle. use one set id for the operation, capture every fixed voter, and run `yoq cluster verify-set` on the complete set. each voter must have applied the cluster ca bootstrap; the ca identity binds bundles to the original cluster.

restore into fresh data roots with the original node ids and voter set, then restart the voters before agents. bundles contain private credentials and need protected storage. they exclude volume data, object bytes, image caches, and agent enrollment. the [cluster recovery procedure](cluster-guide.md#offline-cluster-backup-and-restore) gives the commands and a recovery drill.
