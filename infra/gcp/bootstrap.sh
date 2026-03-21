#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

require_state
ensure_dirs
write_local_api_token

LOCAL_YOQ="${YOQ_BINARY_PATH:-${REPO_ROOT}/zig-out/bin/yoq}"
[ -x "${LOCAL_YOQ}" ] || die "missing local yoq binary at ${LOCAL_YOQ}; run infra/gcp/install.sh first"

log "starting server 1"
gcloud_ssh "${SERVER_1_NAME}" \
  "sudo bash -lc 'pkill -f \"yoq init-server\" || true; nohup env HOME=/root yoq init-server --id 1 --port ${RAFT_PORT} --api-port ${API_PORT} --token ${CLUSTER_JOIN_TOKEN} --api-token ${API_TOKEN} >/var/log/yoq-server.log 2>&1 &'"

sleep 5

log "starting server 2"
gcloud_ssh "${SERVER_2_NAME}" \
  "sudo bash -lc 'pkill -f \"yoq init-server\" || true; nohup env HOME=/root yoq init-server --id 2 --port ${RAFT_PORT} --api-port ${API_PORT} --peers 1@${SERVER_1_INTERNAL_IP}:${RAFT_PORT} --token ${CLUSTER_JOIN_TOKEN} --api-token ${API_TOKEN} >/var/log/yoq-server.log 2>&1 &'"

log "starting server 3"
gcloud_ssh "${SERVER_3_NAME}" \
  "sudo bash -lc 'pkill -f \"yoq init-server\" || true; nohup env HOME=/root yoq init-server --id 3 --port ${RAFT_PORT} --api-port ${API_PORT} --peers 1@${SERVER_1_INTERNAL_IP}:${RAFT_PORT},2@${SERVER_2_INTERNAL_IP}:${RAFT_PORT} --token ${CLUSTER_JOIN_TOKEN} --api-token ${API_TOKEN} >/var/log/yoq-server.log 2>&1 &'"

wait_for_cluster() {
  local tries=0
  while [ "${tries}" -lt 60 ]; do
    if status_json="$(http_get_json "${SERVER_1_EXTERNAL_IP}" "/cluster/status" 2>/dev/null)"; then
      if printf '%s' "${status_json}" | jq -e '.cluster == true and .leader_id != null' >/dev/null 2>&1; then
        printf '%s\n' "${status_json}"
        return 0
      fi
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
  gcloud_ssh "${instance}" \
    "sudo bash -lc 'pkill -f \"yoq join\" || true; nohup env HOME=/root yoq join ${SERVER_1_INTERNAL_IP} --token ${CLUSTER_JOIN_TOKEN} --port ${API_PORT} --role agent >/var/log/yoq-agent.log 2>&1 &'"
}

join_agent "${AGENT_1_NAME}"
join_agent "${AGENT_2_NAME}"

wait_for_agents() {
  local tries=0
  while [ "${tries}" -lt 60 ]; do
    if HOME="${LOCAL_HOME}" "${LOCAL_YOQ}" nodes --server "${SERVER_1_EXTERNAL_IP}:${API_PORT}" --json > "${ARTIFACT_DIR}/nodes-bootstrap.json" 2>/dev/null; then
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
