#!/usr/bin/env bash
set -euo pipefail

readonly GCP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${GCP_DIR}/../.." && pwd)"
readonly DEFAULT_CONFIG="${GCP_DIR}/config.env"
readonly STATE_ROOT="${YOQ_GCP_STATE_DIR:-${GCP_DIR}/.state}"
readonly ARTIFACT_ROOT="${YOQ_GCP_ARTIFACT_DIR:-${GCP_DIR}/artifacts}"

log() {
  printf '[yoq-gcp] %s\n' "$*" >&2
}

die() {
  log "error: $*"
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

sanitize_label() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9-' '-' | sed -E 's/^-+//; s/-+$//; s/-+/-/g'
}

pick_region_zone() {
  local zone
  zone="$(
    gcloud compute zones list \
      --project="${PROJECT_ID}" \
      --filter="region:(${REGION}) AND status=UP" \
      --format='value(name)' |
      sort |
      head -n1
  )"
  [ -n "${zone}" ] || die "could not auto-select a zone in ${REGION}; set ZONE explicitly"
  printf '%s\n' "${zone}"
}

pick_gpu_zone() {
  local zones
  zones="$(
    gcloud compute accelerator-types list \
      --project="${PROJECT_ID}" \
      --format='json(name,zone)' |
      jq -r --arg gpu "${GPU_TYPE}" --arg region "${REGION}" '
        [.[] | select(.name == $gpu) | .zone | split("/")[-1] | select(startswith($region + "-"))] |
        unique | sort | .[0] // empty
      '
  )"
  [ -n "${zones}" ] || die "could not auto-select a zone for ${GPU_TYPE} in ${REGION}; set ZONE explicitly"
  printf '%s\n' "${zones}"
}

pick_gpu_image_family() {
  local family
  family="$(
    gcloud compute images list \
      --project="${GPU_IMAGE_PROJECT}" \
      --no-standard-images \
      --format='json(family,status,creationTimestamp)' |
      jq -r '
        [.[] |
          select(.status == "READY") |
          select((.family // "") | test("^common-.*ubuntu-2204")) |
          .family
        ] | unique | sort | .[-1] // empty
      '
  )"
  [ -n "${family}" ] || die "could not auto-detect a Deep Learning VM image family; set GPU_IMAGE_FAMILY explicitly"
  printf '%s\n' "${family}"
}

require_gpu_quota() {
  local quota_json quota_limit
  quota_json="$(
    gcloud compute project-info describe \
      --project="${PROJECT_ID}" \
      --format='json(quotas)' |
      jq -r '
        .quotas
        | map(select((.metric // .name // "") == "GPUS_ALL_REGIONS"))
        | .[0] // empty
      '
  )"
  [ -n "${quota_json}" ] || die "could not read GPUS_ALL_REGIONS quota for ${PROJECT_ID}; request GPU quota in GCP or set up a CPU-only rig"

  quota_limit="$(
    jq -r '.limit // .hardLimit // 0' <<< "${quota_json}"
  )"

  if awk -v limit="${quota_limit}" 'BEGIN { exit !(limit + 0 > 0) }'; then
    return 0
  fi

  die "project ${PROJECT_ID} has no GPU quota (GPUS_ALL_REGIONS limit is ${quota_limit}); request GPU quota in GCP before creating GPU agents"
}

load_config_base() {
  require_cmd gcloud
  require_cmd jq
  require_cmd openssl
  require_cmd ssh
  require_cmd scp

  CONFIG_FILE="${YOQ_GCP_CONFIG:-${DEFAULT_CONFIG}}"
  [ -f "${CONFIG_FILE}" ] || die "missing config file: ${CONFIG_FILE} (copy infra/gcp/config.env.example first)"

  # shellcheck disable=SC1090
  source "${CONFIG_FILE}"

  : "${PROJECT_ID:?set PROJECT_ID in ${CONFIG_FILE}}"
  : "${REGION:?set REGION in ${CONFIG_FILE}}"

  USE_GPU_AGENTS="${USE_GPU_AGENTS:-false}"
  if [ "${USE_GPU_AGENTS}" = "true" ]; then
    : "${GPU_TYPE:?set GPU_TYPE in ${CONFIG_FILE}}"
  else
    GPU_TYPE="${GPU_TYPE:-}"
  fi

  if [ "${CPU_IMAGE_FAMILY:-}" = "ubuntu-2204-lts-amd64" ]; then
    CPU_IMAGE_FAMILY="ubuntu-2204-lts"
    log "translated legacy CPU image family ubuntu-2204-lts-amd64 -> ${CPU_IMAGE_FAMILY}"
  fi
  CPU_IMAGE_FAMILY="${CPU_IMAGE_FAMILY:-ubuntu-2204-lts}"
  CPU_IMAGE_PROJECT="${CPU_IMAGE_PROJECT:-ubuntu-os-cloud}"

  AGENT_IMAGE_PROJECT="${AGENT_IMAGE_PROJECT:-${CPU_IMAGE_PROJECT}}"
  AGENT_IMAGE_FAMILY="${AGENT_IMAGE_FAMILY:-${CPU_IMAGE_FAMILY}}"
  AGENT_MACHINE_TYPE="${AGENT_MACHINE_TYPE:-${SERVER_MACHINE_TYPE:-e2-standard-2}}"
  AGENT_DISK_GB="${AGENT_DISK_GB:-${SERVER_DISK_GB:-30}}"

  RIG_NAME="${RIG_NAME:-yoq-gcp-$(date +%Y%m%d-%H%M%S)}"
  RIG_LABEL="$(sanitize_label "${RIG_NAME}")"

  NETWORK_NAME="${NETWORK_NAME:-${RIG_LABEL}-net}"
  SUBNET_NAME="${SUBNET_NAME:-${RIG_LABEL}-subnet}"
  HTTP_PROXY_PORT="${HTTP_PROXY_PORT:-17080}"

  SERVER_1_NAME="${RIG_LABEL}-s1"
  SERVER_2_NAME="${RIG_LABEL}-s2"
  SERVER_3_NAME="${RIG_LABEL}-s3"
  AGENT_1_NAME="${RIG_LABEL}-g1"
  AGENT_2_NAME="${RIG_LABEL}-g2"

  STATE_DIR="${STATE_ROOT}/${RIG_LABEL}"
  STATE_FILE="${STATE_DIR}/cluster.env"
  LOCAL_HOME="${STATE_DIR}/local-home"
  LOCAL_DATA_DIR="${LOCAL_HOME}/.local/share/yoq"
  ARTIFACT_DIR="${ARTIFACT_ROOT}/${RIG_LABEL}"
}

load_config() {
  load_config_base

  if [ -z "${ZONE:-}" ]; then
    if [ "${USE_GPU_AGENTS}" = "true" ]; then
      ZONE="$(pick_gpu_zone)"
      log "auto-selected zone ${ZONE} for ${GPU_TYPE}"
    else
      ZONE="$(pick_region_zone)"
      log "auto-selected zone ${ZONE} for ${REGION}"
    fi
  fi

  if [ "${USE_GPU_AGENTS}" = "true" ]; then
    if [ -z "${GPU_IMAGE_FAMILY:-}" ]; then
      GPU_IMAGE_FAMILY="$(pick_gpu_image_family)"
      log "auto-selected GPU image family ${GPU_IMAGE_FAMILY}"
    fi
    AGENT_IMAGE_PROJECT="${GPU_IMAGE_PROJECT}"
    AGENT_IMAGE_FAMILY="${GPU_IMAGE_FAMILY}"
    AGENT_MACHINE_TYPE="${GPU_MACHINE_TYPE}"
    AGENT_DISK_GB="${GPU_DISK_GB}"
    require_gpu_quota
  fi
}

require_state() {
  load_config_base
  STATE_FILE="$(locate_state_file)" || die "missing state file under ${STATE_ROOT}; run infra/gcp/up.sh first"
  # shellcheck disable=SC1090
  source "${STATE_FILE}"
  refresh_instance_ips
  save_state_file
}

locate_state_file() {
  local candidates=()
  if [ -f "${STATE_FILE}" ]; then
    printf '%s\n' "${STATE_FILE}"
    return 0
  fi

  if [ -e "${STATE_ROOT}/current" ]; then
    printf '%s\n' "${STATE_ROOT}/current"
    return 0
  fi

  while IFS= read -r candidate; do
    [ -n "${candidate}" ] && candidates+=("${candidate}")
  done < <(find "${STATE_ROOT}" -mindepth 2 -maxdepth 2 -name cluster.env -print 2>/dev/null | sort)

  if [ "${#candidates[@]}" -eq 1 ]; then
    printf '%s\n' "${candidates[0]}"
    return 0
  fi

  if [ "${#candidates[@]}" -gt 1 ]; then
    die "multiple GCP rig states exist under ${STATE_ROOT}; set RIG_NAME explicitly or remove old states"
  fi

  return 1
}

ensure_dirs() {
  mkdir -p "${STATE_DIR}" "${ARTIFACT_DIR}" "${LOCAL_DATA_DIR}"
}

write_local_api_token() {
  mkdir -p "${LOCAL_DATA_DIR}"
  printf '%s' "${API_TOKEN}" > "${LOCAL_DATA_DIR}/api_token"
  chmod 600 "${LOCAL_DATA_DIR}/api_token"
}

gcloud_ssh() {
  local instance="$1"
  shift
  gcloud compute ssh "${instance}" \
    --project="${PROJECT_ID}" \
    --zone="${ZONE}" \
    --ssh-flag='-o' \
    --ssh-flag='StrictHostKeyChecking=no' \
    --ssh-flag='-o' \
    --ssh-flag='UserKnownHostsFile=/dev/null' \
    --command "$*"
}

gcloud_scp_to() {
  local src="$1"
  local instance="$2"
  local dst="$3"
  gcloud compute scp "${src}" "${instance}:${dst}" \
    --project="${PROJECT_ID}" \
    --zone="${ZONE}" \
    --scp-flag='-o' \
    --scp-flag='StrictHostKeyChecking=no' \
    --scp-flag='-o' \
    --scp-flag='UserKnownHostsFile=/dev/null'
}

instance_ip() {
  local instance="$1"
  local field="$2"
  case "${field}" in
    external)
      gcloud compute instances describe "${instance}" \
        --project="${PROJECT_ID}" \
        --zone="${ZONE}" \
        --format='get(networkInterfaces[0].accessConfigs[0].natIP)'
      ;;
    internal)
      gcloud compute instances describe "${instance}" \
        --project="${PROJECT_ID}" \
        --zone="${ZONE}" \
        --format='get(networkInterfaces[0].networkIP)'
      ;;
    *)
      die "unknown instance_ip field: ${field}"
      ;;
  esac
}

validate_ip() {
  local label="$1" value="$2"
  if [ -z "${value}" ]; then
    die "${label} is empty; instance may not be running"
  fi
  if ! printf '%s' "${value}" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
    die "${label} is not a valid IPv4 address: ${value}"
  fi
}

refresh_instance_ips() {
  SERVER_1_EXTERNAL_IP="$(instance_ip "${SERVER_1_NAME}" external)"
  SERVER_2_EXTERNAL_IP="$(instance_ip "${SERVER_2_NAME}" external)"
  SERVER_3_EXTERNAL_IP="$(instance_ip "${SERVER_3_NAME}" external)"
  AGENT_1_EXTERNAL_IP="$(instance_ip "${AGENT_1_NAME}" external)"
  AGENT_2_EXTERNAL_IP="$(instance_ip "${AGENT_2_NAME}" external)"

  SERVER_1_INTERNAL_IP="$(instance_ip "${SERVER_1_NAME}" internal)"
  SERVER_2_INTERNAL_IP="$(instance_ip "${SERVER_2_NAME}" internal)"
  SERVER_3_INTERNAL_IP="$(instance_ip "${SERVER_3_NAME}" internal)"
  AGENT_1_INTERNAL_IP="$(instance_ip "${AGENT_1_NAME}" internal)"
  AGENT_2_INTERNAL_IP="$(instance_ip "${AGENT_2_NAME}" internal)"

  local var
  for var in SERVER_1_EXTERNAL_IP SERVER_2_EXTERNAL_IP SERVER_3_EXTERNAL_IP \
             AGENT_1_EXTERNAL_IP AGENT_2_EXTERNAL_IP \
             SERVER_1_INTERNAL_IP SERVER_2_INTERNAL_IP SERVER_3_INTERNAL_IP \
             AGENT_1_INTERNAL_IP AGENT_2_INTERNAL_IP; do
    validate_ip "${var}" "${!var}"
  done
}

instance_status() {
  local instance="$1"
  gcloud compute instances describe "${instance}" \
    --project="${PROJECT_ID}" \
    --zone="${ZONE}" \
    --format='get(status)'
}

wait_for_ssh() {
  local instance="$1"
  local tries=0
  while [ "${tries}" -lt 60 ]; do
    if gcloud_ssh "${instance}" 'echo ready' >/dev/null 2>&1; then
      gcloud_ssh "${instance}" 'test -f /var/lib/cloud/instance/boot-finished || cloud-init status --wait >/dev/null 2>&1 || true' >/dev/null 2>&1 || true
      return 0
    fi
    tries=$((tries + 1))
    sleep 10
  done
  return 1
}

http_get_json() {
  local addr="$1"
  local path="$2"
  curl -fsS \
    -H "Authorization: Bearer ${API_TOKEN}" \
    "http://${addr}:${API_PORT}${path}"
}

save_state_file() {
  cat > "${STATE_FILE}" <<EOF
PROJECT_ID=${PROJECT_ID@Q}
REGION=${REGION@Q}
ZONE=${ZONE@Q}
RIG_NAME=${RIG_NAME@Q}
RIG_LABEL=${RIG_LABEL@Q}
NETWORK_NAME=${NETWORK_NAME@Q}
SUBNET_NAME=${SUBNET_NAME@Q}
API_PORT=${API_PORT@Q}
HTTP_PROXY_PORT=${HTTP_PROXY_PORT@Q}
RAFT_PORT=${RAFT_PORT@Q}
GOSSIP_PORT=${GOSSIP_PORT@Q}
WIREGUARD_PORT=${WIREGUARD_PORT@Q}
CPU_IMAGE_PROJECT=${CPU_IMAGE_PROJECT@Q}
CPU_IMAGE_FAMILY=${CPU_IMAGE_FAMILY@Q}
GPU_IMAGE_PROJECT=${GPU_IMAGE_PROJECT@Q}
GPU_IMAGE_FAMILY=${GPU_IMAGE_FAMILY@Q}
GPU_TYPE=${GPU_TYPE@Q}
GPU_COUNT_PER_AGENT=${GPU_COUNT_PER_AGENT@Q}
USE_GPU_AGENTS=${USE_GPU_AGENTS@Q}
AGENT_IMAGE_PROJECT=${AGENT_IMAGE_PROJECT@Q}
AGENT_IMAGE_FAMILY=${AGENT_IMAGE_FAMILY@Q}
AGENT_MACHINE_TYPE=${AGENT_MACHINE_TYPE@Q}
AGENT_DISK_GB=${AGENT_DISK_GB@Q}
SERVER_MACHINE_TYPE=${SERVER_MACHINE_TYPE@Q}
GPU_MACHINE_TYPE=${GPU_MACHINE_TYPE@Q}
SERVER_DISK_GB=${SERVER_DISK_GB@Q}
GPU_DISK_GB=${GPU_DISK_GB@Q}
GPU_SMOKE_IMAGE=${GPU_SMOKE_IMAGE@Q}
TRAIN_IMAGE=${TRAIN_IMAGE@Q}
SERVER_1_NAME=${SERVER_1_NAME@Q}
SERVER_2_NAME=${SERVER_2_NAME@Q}
SERVER_3_NAME=${SERVER_3_NAME@Q}
AGENT_1_NAME=${AGENT_1_NAME@Q}
AGENT_2_NAME=${AGENT_2_NAME@Q}
SERVER_1_INTERNAL_IP=${SERVER_1_INTERNAL_IP@Q}
SERVER_2_INTERNAL_IP=${SERVER_2_INTERNAL_IP@Q}
SERVER_3_INTERNAL_IP=${SERVER_3_INTERNAL_IP@Q}
AGENT_1_INTERNAL_IP=${AGENT_1_INTERNAL_IP@Q}
AGENT_2_INTERNAL_IP=${AGENT_2_INTERNAL_IP@Q}
SERVER_1_EXTERNAL_IP=${SERVER_1_EXTERNAL_IP@Q}
SERVER_2_EXTERNAL_IP=${SERVER_2_EXTERNAL_IP@Q}
SERVER_3_EXTERNAL_IP=${SERVER_3_EXTERNAL_IP@Q}
AGENT_1_EXTERNAL_IP=${AGENT_1_EXTERNAL_IP@Q}
AGENT_2_EXTERNAL_IP=${AGENT_2_EXTERNAL_IP@Q}
CLUSTER_JOIN_TOKEN=${CLUSTER_JOIN_TOKEN@Q}
API_TOKEN=${API_TOKEN@Q}
LOCAL_HOME=${LOCAL_HOME@Q}
ARTIFACT_DIR=${ARTIFACT_DIR@Q}
EOF
}
