#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

require_state
ensure_dirs

require_cmd zig

YOQ_BINARY="${YOQ_BINARY_PATH:-${REPO_ROOT}/zig-out/bin/yoq}"
if [ ! -x "${YOQ_BINARY}" ]; then
  log "building local yoq binary"
  (cd "${REPO_ROOT}" && zig build -Doptimize=ReleaseSafe)
fi
[ -x "${YOQ_BINARY}" ] || die "missing built yoq binary at ${YOQ_BINARY}"

for instance in \
  "${SERVER_1_NAME}" "${SERVER_2_NAME}" "${SERVER_3_NAME}" \
  "${AGENT_1_NAME}" "${AGENT_2_NAME}"; do
  log "copying yoq and helpers to ${instance}"
  gcloud_scp_to "${YOQ_BINARY}" "${instance}" "/tmp/yoq"
  gcloud_scp_to "${GCP_DIR}/remote/install-node.sh" "${instance}" "/tmp/install-node.sh"
  gcloud_scp_to "${GCP_DIR}/train/smoke.py" "${instance}" "/tmp/smoke.py"
done

install_remote() {
  local instance="$1"
  local role="$2"
  log "installing runtime packages and yoq on ${instance}"
  gcloud_ssh "${instance}" "sudo bash /tmp/install-node.sh ${role}"
}

install_remote "${SERVER_1_NAME}" server
install_remote "${SERVER_2_NAME}" server
install_remote "${SERVER_3_NAME}" server
agent_role="agent-cpu"
[ "${USE_GPU_AGENTS}" = "true" ] && agent_role="agent-gpu"

install_remote "${AGENT_1_NAME}" "${agent_role}"
install_remote "${AGENT_2_NAME}" "${agent_role}"

for instance in "${SERVER_1_NAME}" "${SERVER_2_NAME}" "${SERVER_3_NAME}"; do
  log "checking doctor output on ${instance}"
  gcloud_ssh "${instance}" "sudo test -s /opt/yoq-gcp/doctor.json"
done

if [ "${USE_GPU_AGENTS}" = "true" ]; then
  for instance in "${AGENT_1_NAME}" "${AGENT_2_NAME}"; do
    log "checking GPU visibility on ${instance}"
    gcloud_ssh "${instance}" "sudo nvidia-smi -L >/dev/null"
  done
else
  for instance in "${AGENT_1_NAME}" "${AGENT_2_NAME}"; do
    log "checking agent runtime on ${instance}"
    gcloud_ssh "${instance}" "sudo test -s /opt/yoq-gcp/doctor.json"
  done
fi

log "installation complete"
