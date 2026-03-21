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
