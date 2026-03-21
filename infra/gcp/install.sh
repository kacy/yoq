#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

require_state
ensure_dirs

YOQ_INSTALL_URL="${YOQ_INSTALL_URL:-https://yoq.dev/install}"

for instance in \
  "${SERVER_1_NAME}" "${SERVER_2_NAME}" "${SERVER_3_NAME}" \
  "${AGENT_1_NAME}" "${AGENT_2_NAME}"; do
  log "copying helpers to ${instance}"
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

install_yoq_remote() {
  local instance="$1"
  log "installing yoq release on ${instance}"
  gcloud_ssh "${instance}" "sudo bash -lc 'curl -fsSL ${YOQ_INSTALL_URL} | bash'"
}

install_yoq_remote "${SERVER_1_NAME}"
install_yoq_remote "${SERVER_2_NAME}"
install_yoq_remote "${SERVER_3_NAME}"
install_yoq_remote "${AGENT_1_NAME}"
install_yoq_remote "${AGENT_2_NAME}"

for instance in "${SERVER_1_NAME}" "${SERVER_2_NAME}" "${SERVER_3_NAME}"; do
  log "checking doctor output on ${instance}"
  gcloud_ssh "${instance}" "sudo bash -lc 'HOME=/root yoq doctor --json > /opt/yoq-gcp/doctor.json'"
done

for instance in "${AGENT_1_NAME}" "${AGENT_2_NAME}"; do
  log "checking doctor output on ${instance}"
  gcloud_ssh "${instance}" "sudo bash -lc 'HOME=/root yoq doctor --json > /opt/yoq-gcp/doctor.json'"
done

if [ "${USE_GPU_AGENTS}" = "true" ]; then
  for instance in "${AGENT_1_NAME}" "${AGENT_2_NAME}"; do
    log "checking GPU visibility on ${instance}"
    gcloud_ssh "${instance}" "sudo nvidia-smi -L >/dev/null"
  done
fi

log "installation complete"
