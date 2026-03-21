#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

require_state
ensure_dirs
write_local_api_token

wait_for_remote_shell() {
  local instance="$1"
  local tries=0
  while [ "${tries}" -lt 12 ]; do
    if gcloud_ssh "${instance}" 'echo ready' >/dev/null 2>&1; then
      return 0
    fi
    tries=$((tries + 1))
    sleep 5
  done
  return 1
}

for instance in "${SERVER_1_NAME}" "${SERVER_2_NAME}" "${SERVER_3_NAME}" "${AGENT_1_NAME}" "${AGENT_2_NAME}"; do
  log "waiting for SSH access on ${instance}"
  wait_for_remote_shell "${instance}" || die "SSH access never stabilized on ${instance}"
  gcloud_scp_to "${GCP_DIR}/remote/start-node.sh" "${instance}" "/tmp/start-node.sh"
done

log "starting server 1"
gcloud_ssh "${SERVER_1_NAME}" "sudo bash /tmp/start-node.sh server 1 ${RAFT_PORT} ${API_PORT} ${CLUSTER_JOIN_TOKEN} ${API_TOKEN} 2@${SERVER_2_INTERNAL_IP}:${RAFT_PORT} 3@${SERVER_3_INTERNAL_IP}:${RAFT_PORT}"

sleep 5

log "starting server 2"
gcloud_ssh "${SERVER_2_NAME}" "sudo bash /tmp/start-node.sh server 2 ${RAFT_PORT} ${API_PORT} ${CLUSTER_JOIN_TOKEN} ${API_TOKEN} 1@${SERVER_1_INTERNAL_IP}:${RAFT_PORT} 3@${SERVER_3_INTERNAL_IP}:${RAFT_PORT}"

log "starting server 3"
gcloud_ssh "${SERVER_3_NAME}" "sudo bash /tmp/start-node.sh server 3 ${RAFT_PORT} ${API_PORT} ${CLUSTER_JOIN_TOKEN} ${API_TOKEN} 1@${SERVER_1_INTERNAL_IP}:${RAFT_PORT} 2@${SERVER_2_INTERNAL_IP}:${RAFT_PORT}"

wait_for_cluster() {
  local tries=0
  local probed=0
  while [ "${tries}" -lt 60 ]; do
    if status_json="$(http_get_json "${SERVER_1_EXTERNAL_IP}" "/cluster/status" 2>/dev/null)"; then
      if printf '%s' "${status_json}" | jq -e '.cluster == true and .leader_id != null' >/dev/null 2>&1; then
        printf '%s\n' "${status_json}"
        return 0
      fi
    fi
    if [ "${probed}" -eq 0 ] && [ "${tries}" -ge 12 ]; then
      probed=1
      log "leader election still pending after 60s; collecting bootstrap diagnostics"
      mkdir -p "${ARTIFACT_DIR}/bootstrap-probe"
      if status_json="$(http_get_json "${SERVER_1_EXTERNAL_IP}" "/cluster/status" 2>/dev/null)"; then
        printf '%s\n' "${status_json}" > "${ARTIFACT_DIR}/bootstrap-probe/cluster-status.json"
      fi
      for instance in "${SERVER_1_NAME}" "${SERVER_2_NAME}" "${SERVER_3_NAME}"; do
        gcloud_ssh "${instance}" "sudo tail -n 200 /var/log/yoq-server.log" \
          > "${ARTIFACT_DIR}/bootstrap-probe/${instance}.log" 2>&1 || true
      done
    fi
    tries=$((tries + 1))
    sleep 5
  done
  return 1
}

log "waiting for raft leader election"
wait_for_cluster > "${ARTIFACT_DIR}/cluster-status-bootstrap.json" || die "cluster never reported a leader"

join_agent() {
  local instance="$1"
  log "joining ${instance} as agent"
  gcloud_ssh "${instance}" "sudo bash /tmp/start-node.sh agent ${SERVER_1_INTERNAL_IP} ${CLUSTER_JOIN_TOKEN} ${API_PORT}"
}

join_agent "${AGENT_1_NAME}"
join_agent "${AGENT_2_NAME}"

wait_for_agents() {
  local tries=0
  while [ "${tries}" -lt 60 ]; do
    if http_get_json "${SERVER_1_EXTERNAL_IP}" "/agents" > "${ARTIFACT_DIR}/nodes-bootstrap.json" 2>/dev/null; then
      if jq -e 'length == 2 and all(.[]; .status == "active" and .overlay_ip != null)' "${ARTIFACT_DIR}/nodes-bootstrap.json" >/dev/null 2>&1; then
        return 0
      fi
    fi
    tries=$((tries + 1))
    sleep 5
  done
  return 1
}

log "waiting for both agents to join"
wait_for_agents || die "agents did not join cleanly"

log "bootstrap complete"
