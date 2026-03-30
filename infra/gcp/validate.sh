#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

require_state
ensure_dirs
write_local_api_token

LOCAL_YOQ="${YOQ_BINARY_PATH:-${REPO_ROOT}/zig-out/bin/yoq}"
[ -x "${LOCAL_YOQ}" ] || die "missing local yoq binary at ${LOCAL_YOQ}"

RUN_DIR="${ARTIFACT_DIR}/$(date +%Y%m%d-%H%M%S)"
mkdir -p "${RUN_DIR}"

log "capturing cluster status"
http_get_json "${SERVER_1_EXTERNAL_IP}" "/cluster/status" > "${RUN_DIR}/cluster-status.json"
HOME="${LOCAL_HOME}" "${LOCAL_YOQ}" nodes --server "${SERVER_1_EXTERNAL_IP}:${API_PORT}" --json > "${RUN_DIR}/nodes.json"
jq -e 'length == 2 and all(.[]; .status == "active" and .overlay_ip != null)' "${RUN_DIR}/nodes.json" >/dev/null || \
  die "cluster does not report two active agents"

current_leader_id() {
  local status_json="$1"
  jq -r '.leader_id // empty' <<< "${status_json}"
}

server_name_by_id() {
  local id="$1"
  case "${id}" in
    1) printf '%s\n' "${SERVER_1_NAME}" ;;
    2) printf '%s\n' "${SERVER_2_NAME}" ;;
    3) printf '%s\n' "${SERVER_3_NAME}" ;;
    *) return 1 ;;
  esac
}

leader_external_ip() {
  local leader_id="$1"
  case "${leader_id}" in
    1) printf '%s\n' "${SERVER_1_EXTERNAL_IP}" ;;
    2) printf '%s\n' "${SERVER_2_EXTERNAL_IP}" ;;
    3) printf '%s\n' "${SERVER_3_EXTERNAL_IP}" ;;
    *) return 1 ;;
  esac
}

wait_for_new_leader() {
  local old_leader_id="$1"
  local tries=0
  while [ "${tries}" -lt 24 ]; do
    local status_json
    if status_json="$(http_get_json "${SERVER_1_EXTERNAL_IP}" "/cluster/status" 2>/dev/null)"; then
      local new_leader_id
      new_leader_id="$(current_leader_id "${status_json}")"
      if [ -n "${new_leader_id}" ] && [ "${new_leader_id}" != "${old_leader_id}" ]; then
        printf '%s\n' "${status_json}"
        return 0
      fi
    fi
    tries=$((tries + 1))
    sleep 5
  done
  return 1
}

server_peer_arg() {
  local id="$1"
  case "${id}" in
    1) printf '%s\n' "2@${SERVER_2_INTERNAL_IP}:${RAFT_PORT} 3@${SERVER_3_INTERNAL_IP}:${RAFT_PORT}" ;;
    2) printf '%s\n' "1@${SERVER_1_INTERNAL_IP}:${RAFT_PORT} 3@${SERVER_3_INTERNAL_IP}:${RAFT_PORT}" ;;
    3) printf '%s\n' "1@${SERVER_1_INTERNAL_IP}:${RAFT_PORT} 2@${SERVER_2_INTERNAL_IP}:${RAFT_PORT}" ;;
    *) return 1 ;;
  esac
}

wait_for_server_api() {
  local server_ip="$1"
  local tries=0
  while [ "${tries}" -lt 24 ]; do
    if http_get_json "${server_ip}" "/cluster/status" >/dev/null 2>&1; then
      return 0
    fi
    tries=$((tries + 1))
    sleep 5
  done
  return 1
}

wait_for_routed_response() {
  local addr="$1"
  local host="$2"
  local path="$3"
  local expected="$4"
  local tries=0
  while [ "${tries}" -lt 24 ]; do
    local body
    body="$(curl -fsS --max-time 10 -H "Host: ${host}" "http://${addr}:${HTTP_PROXY_PORT}${path}" 2>/dev/null || true)"
    if printf '%s' "${body}" | grep -Fq "${expected}"; then
      printf '%s\n' "${body}"
      return 0
    fi
    tries=$((tries + 1))
    sleep 5
  done
  return 1
}

wait_for_agent_active() {
  local overlay_ip="$1"
  local tries=0
  while [ "${tries}" -lt 24 ]; do
    local nodes_json
    if nodes_json="$(HOME="${LOCAL_HOME}" "${LOCAL_YOQ}" nodes --server "${SERVER_1_EXTERNAL_IP}:${API_PORT}" --json 2>/dev/null)"; then
      if jq -e --arg overlay_ip "${overlay_ip}" '
        any(.[]; .overlay_ip == $overlay_ip and .status == "active")
      ' <<< "${nodes_json}" >/dev/null 2>&1; then
        printf '%s\n' "${nodes_json}"
        return 0
      fi
    fi
    tries=$((tries + 1))
    sleep 5
  done
  return 1
}

AGENT_1_OVERLAY_IP="$(jq -r '.[0].overlay_ip' "${RUN_DIR}/nodes.json")"
AGENT_2_OVERLAY_IP="$(jq -r '.[1].overlay_ip' "${RUN_DIR}/nodes.json")"

for instance in \
  "${SERVER_1_NAME}" "${SERVER_2_NAME}" "${SERVER_3_NAME}" \
  "${AGENT_1_NAME}" "${AGENT_2_NAME}"; do
  log "collecting doctor output from ${instance}"
  gcloud_ssh "${instance}" "sudo cat /opt/yoq-gcp/doctor.json" > "${RUN_DIR}/${instance}-doctor.json"
done

log "verifying WireGuard interfaces"
for instance in "${SERVER_1_NAME}" "${SERVER_2_NAME}" "${SERVER_3_NAME}" "${AGENT_1_NAME}" "${AGENT_2_NAME}"; do
  gcloud_ssh "${instance}" "sudo ip link show wg-yoq >/dev/null"
done

log "verifying overlay reachability between agents"
gcloud_ssh "${AGENT_1_NAME}" "sudo ping -c 2 -W 2 ${AGENT_2_OVERLAY_IP} >/dev/null"
gcloud_ssh "${AGENT_2_NAME}" "sudo ping -c 2 -W 2 ${AGENT_1_OVERLAY_IP} >/dev/null"

log "verifying leader failover"
INITIAL_CLUSTER_STATUS="$(cat "${RUN_DIR}/cluster-status.json")"
INITIAL_LEADER_ID="$(current_leader_id "${INITIAL_CLUSTER_STATUS}")"
[ -n "${INITIAL_LEADER_ID}" ] || die "cluster status did not include a leader id"
INITIAL_LEADER_IP="$(leader_external_ip "${INITIAL_LEADER_ID}")" || die "unknown leader id ${INITIAL_LEADER_ID}"
curl -fsS -X POST -H "Authorization: Bearer ${API_TOKEN}" "http://${INITIAL_LEADER_IP}:${API_PORT}/cluster/step-down" \
  > "${RUN_DIR}/leader-step-down.json"
wait_for_new_leader "${INITIAL_LEADER_ID}" > "${RUN_DIR}/cluster-status-after-step-down.json" || \
  die "cluster did not elect a new leader after step-down"
CURRENT_LEADER_ID="$(current_leader_id "$(cat "${RUN_DIR}/cluster-status-after-step-down.json")")"
CURRENT_LEADER_IP="$(leader_external_ip "${CURRENT_LEADER_ID}")" || die "unknown leader id ${CURRENT_LEADER_ID}"

log "verifying agent restart and recovery"
gcloud_ssh "${AGENT_1_NAME}" "sudo bash /tmp/start-node.sh agent ${SERVER_1_INTERNAL_IP} ${CLUSTER_JOIN_TOKEN} ${API_PORT}"
wait_for_agent_active "${AGENT_1_OVERLAY_IP}" > "${RUN_DIR}/nodes-after-agent-restart.json" || \
  die "restarted agent did not return to active state"
gcloud_ssh "${AGENT_2_NAME}" "sudo ping -c 2 -W 2 ${AGENT_1_OVERLAY_IP} >/dev/null"

RESTART_SERVER_ID=1
if [ "${CURRENT_LEADER_ID}" = "1" ]; then
  RESTART_SERVER_ID=2
fi
RESTART_SERVER_NAME="$(server_name_by_id "${RESTART_SERVER_ID}")" || die "unknown restart server ${RESTART_SERVER_ID}"
RESTART_SERVER_IP="$(leader_external_ip "${RESTART_SERVER_ID}")" || die "unknown restart server ip ${RESTART_SERVER_ID}"
RESTART_SERVER_PEERS="$(server_peer_arg "${RESTART_SERVER_ID}")" || die "missing peers for restart server ${RESTART_SERVER_ID}"

log "deploying routed workload and verifying server restart recovery"
HOME="${LOCAL_HOME}" "${LOCAL_YOQ}" up \
  --server "${CURRENT_LEADER_IP}:${API_PORT}" \
  -f "${REPO_ROOT}/examples/http-routing/manifest.toml"
wait_for_routed_response "${RESTART_SERVER_IP}" "demo.local" "/" "gateway route" > "${RUN_DIR}/routed-root-before-restart.txt" || \
  die "routed gateway traffic did not become reachable"
wait_for_routed_response "${RESTART_SERVER_IP}" "demo.local" "/api/get" "api route" > "${RUN_DIR}/routed-api-before-restart.txt" || \
  die "routed API traffic did not become reachable"
wait_for_routed_response "${RESTART_SERVER_IP}" "docs.demo.local" "/" "docs route" > "${RUN_DIR}/routed-docs-before-restart.txt" || \
  die "routed docs traffic did not become reachable"
http_get_json "${RESTART_SERVER_IP}" "/v1/status?mode=service_discovery" > "${RUN_DIR}/service-discovery-before-server-restart.json"
jq -e '.listener.running == true and .l7_proxy.routes >= 4 and .control_plane.running == true' \
  "${RUN_DIR}/service-discovery-before-server-restart.json" >/dev/null || \
  die "service discovery status did not show a healthy routed listener before restart"

gcloud_ssh "${RESTART_SERVER_NAME}" \
  "sudo bash /tmp/start-node.sh server-restart ${RESTART_SERVER_ID} ${RAFT_PORT} ${API_PORT} ${HTTP_PROXY_PORT} ${CLUSTER_JOIN_TOKEN} ${API_TOKEN} ${RESTART_SERVER_PEERS}"
wait_for_server_api "${RESTART_SERVER_IP}" || die "restarted server API never came back"
wait_for_routed_response "${RESTART_SERVER_IP}" "demo.local" "/" "gateway route" > "${RUN_DIR}/routed-root-after-server-restart.txt" || \
  die "routed gateway traffic did not recover after server restart"
wait_for_routed_response "${RESTART_SERVER_IP}" "demo.local" "/api/get" "api route" > "${RUN_DIR}/routed-api-after-server-restart.txt" || \
  die "routed API traffic did not recover after server restart"
http_get_json "${RESTART_SERVER_IP}" "/v1/status?mode=service_discovery" > "${RUN_DIR}/service-discovery-after-server-restart.json"
jq -e '.listener.running == true and .l7_proxy.routes >= 4 and .control_plane.running == true' \
  "${RUN_DIR}/service-discovery-after-server-restart.json" >/dev/null || \
  die "service discovery status did not recover after server restart"
http_get_json "${RESTART_SERVER_IP}" "/v1/metrics?format=prometheus" > "${RUN_DIR}/service-discovery-after-server-restart.prom"
grep -Fq 'yoq_service_l7_proxy_listener_running 1' "${RUN_DIR}/service-discovery-after-server-restart.prom" || \
  die "listener metric did not recover after server restart"

cleanup_container() {
  local instance="$1"
  local name="$2"
  gcloud_ssh "${instance}" "sudo bash -lc 'yoq stop ${name} >/dev/null 2>&1 || true; yoq rm ${name} >/dev/null 2>&1 || true'"
}

cleanup_container "${AGENT_1_NAME}" smoke-redis
cleanup_container "${AGENT_1_NAME}" smoke-httpd
cleanup_container "${AGENT_2_NAME}" overlay-web

gcloud_ssh "${AGENT_2_NAME}" "sudo yoq ps --json" > "${RUN_DIR}/${AGENT_2_NAME}-ps-before.json" || printf '[]\n' > "${RUN_DIR}/${AGENT_2_NAME}-ps-before.json"

log "starting several containers directly on the agent nodes"
gcloud_ssh "${AGENT_1_NAME}" "sudo bash -lc 'yoq run -d --name smoke-redis docker.io/library/redis:7-alpine'"
gcloud_ssh "${AGENT_1_NAME}" "sudo bash -lc 'yoq run -d --name smoke-httpd docker.io/library/httpd:2.4-alpine'"
gcloud_ssh "${AGENT_2_NAME}" "sudo bash -lc 'yoq run -d --name overlay-web docker.io/library/nginx:1.27-alpine'"

wait_for_container_ip() {
  local instance="$1"
  local before_ids="$2"
  local tries=0
  while [ "${tries}" -lt 30 ]; do
    local json
    json="$(gcloud_ssh "${instance}" "sudo yoq ps --json" 2>/dev/null || true)"
    local ip
    ip="$(
      jq -r --argjson before "${before_ids}" '
        ($before | map(.id)) as $ids |
        [.[] | select(($ids | index(.id)) | not)] |
        map(select(.status == "running" and .ip != null)) |
        .[0].ip // empty
      ' <<< "${json}"
    )"
    if [ -n "${ip}" ]; then
      printf '%s\n' "${ip}"
      return 0
    fi
    tries=$((tries + 1))
    sleep 2
  done
  return 1
}

OVERLAY_WEB_IP="$(
  wait_for_container_ip \
    "${AGENT_2_NAME}" \
    "$(cat "${RUN_DIR}/${AGENT_2_NAME}-ps-before.json")"
)" || die "overlay-web never became reachable"

log "testing cross-node container networking"
gcloud_ssh "${AGENT_1_NAME}" "curl -fsS --max-time 10 http://${OVERLAY_WEB_IP}" > "${RUN_DIR}/overlay-web.html"
grep -qi 'nginx' "${RUN_DIR}/overlay-web.html" || die "cross-node HTTP smoke did not return nginx content"

if [ "${USE_GPU_AGENTS}" = "true" ]; then
  for agent in "${AGENT_1_NAME}" "${AGENT_2_NAME}"; do
    log "collecting GPU topology from ${agent}"
    gcloud_ssh "${agent}" "sudo yoq gpu topo --json" > "${RUN_DIR}/${agent}-gpu-topo.json"
    gcloud_ssh "${agent}" "sudo nvidia-smi -L" > "${RUN_DIR}/${agent}-nvidia-smi.txt"
    log "running GPU passthrough smoke container on ${agent}"
    gcloud_ssh "${agent}" "sudo yoq run ${GPU_SMOKE_IMAGE} nvidia-smi" > "${RUN_DIR}/${agent}-gpu-container.txt"
  done

  if gcloud_ssh "${AGENT_1_NAME}" "sudo yoq gpu topo --json" | jq -e '.gpus | length >= 2' >/dev/null 2>&1; then
    log "running GPU benchmark on ${AGENT_1_NAME}"
    gcloud_ssh "${AGENT_1_NAME}" "sudo yoq gpu bench --json" > "${RUN_DIR}/${AGENT_1_NAME}-gpu-bench.json"
  fi

  log "starting cluster training env smoke"
  gcloud_ssh "${AGENT_1_NAME}" "sudo bash -lc 'ls -1 /root/.local/share/yoq/logs/*.log 2>/dev/null | sort'" > "${RUN_DIR}/${AGENT_1_NAME}-logs-before.txt" || true
  gcloud_ssh "${AGENT_2_NAME}" "sudo bash -lc 'ls -1 /root/.local/share/yoq/logs/*.log 2>/dev/null | sort'" > "${RUN_DIR}/${AGENT_2_NAME}-logs-before.txt" || true

  HOME="${LOCAL_HOME}" "${LOCAL_YOQ}" train start \
    -f "${GCP_DIR}/manifests/train-smoke.toml" \
    --server "${SERVER_1_EXTERNAL_IP}:${API_PORT}" \
    train-env > "${RUN_DIR}/train-start.txt"

  grep -q '"placed":2' "${RUN_DIR}/train-start.txt" || die "cluster training smoke did not place both GPU ranks"

  sleep 10

  capture_latest_env_log() {
    local instance="$1"
    local baseline="$2"
    local out="$3"
    gcloud_ssh "${instance}" "sudo bash -lc '
      baseline=${baseline@Q}
      latest=\$(
        comm -13 <(printf \"%s\n\" \"\$baseline\" | sed \"/^$/d\" | sort) \
                 <(ls -1 /root/.local/share/yoq/logs/*.log 2>/dev/null | sort) \
          | tail -n1
      )
      if [ -z \"\$latest\" ]; then
        latest=\$(ls -1t /root/.local/share/yoq/logs/*.log 2>/dev/null | head -n1)
      fi
      test -n \"\$latest\"
      cat \"\$latest\"
    '" > "${out}"
  }

  capture_latest_env_log "${AGENT_1_NAME}" "$(cat "${RUN_DIR}/${AGENT_1_NAME}-logs-before.txt" 2>/dev/null || true)" "${RUN_DIR}/${AGENT_1_NAME}-train.log"
  capture_latest_env_log "${AGENT_2_NAME}" "$(cat "${RUN_DIR}/${AGENT_2_NAME}-logs-before.txt" 2>/dev/null || true)" "${RUN_DIR}/${AGENT_2_NAME}-train.log"

  for file in "${RUN_DIR}/${AGENT_1_NAME}-train.log" "${RUN_DIR}/${AGENT_2_NAME}-train.log"; do
    grep -q 'MASTER_ADDR=' "${file}" || die "missing MASTER_ADDR in ${file}"
    grep -q 'WORLD_SIZE=2' "${file}" || die "missing WORLD_SIZE=2 in ${file}"
    grep -q 'RANK=' "${file}" || die "missing RANK in ${file}"
    grep -q 'LOCAL_RANK=' "${file}" || die "missing LOCAL_RANK in ${file}"
  done
else
  log "GPU validation skipped because USE_GPU_AGENTS=false"
fi

log "capturing agent runtime state"
gcloud_ssh "${AGENT_1_NAME}" "sudo yoq ps --json" > "${RUN_DIR}/${AGENT_1_NAME}-ps.json"
gcloud_ssh "${AGENT_2_NAME}" "sudo yoq ps --json" > "${RUN_DIR}/${AGENT_2_NAME}-ps.json"

log "validation succeeded; artifacts are under ${RUN_DIR}"
