#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

load_config
ensure_dirs

[ ! -f "${STATE_FILE}" ] || die "state already exists at ${STATE_FILE}; remove it or run infra/gcp/down.sh first"

require_cmd curl

log "creating VPC network ${NETWORK_NAME}"
gcloud compute networks describe "${NETWORK_NAME}" --project="${PROJECT_ID}" >/dev/null 2>&1 || \
  gcloud compute networks create "${NETWORK_NAME}" \
    --project="${PROJECT_ID}" \
    --subnet-mode=custom

gcloud compute networks subnets describe "${SUBNET_NAME}" --project="${PROJECT_ID}" --region="${REGION}" >/dev/null 2>&1 || \
  gcloud compute networks subnets create "${SUBNET_NAME}" \
    --project="${PROJECT_ID}" \
    --network="${NETWORK_NAME}" \
    --region="${REGION}" \
    --range="${NETWORK_CIDR}"

gcloud compute firewall-rules describe "${RIG_LABEL}-ssh-api" --project="${PROJECT_ID}" >/dev/null 2>&1 || \
  gcloud compute firewall-rules create "${RIG_LABEL}-ssh-api" \
    --project="${PROJECT_ID}" \
    --network="${NETWORK_NAME}" \
    --direction=INGRESS \
    --action=ALLOW \
    --rules="tcp:22,tcp:${API_PORT}" \
    --source-ranges="${SSH_CIDR}" \
    --target-tags="${RIG_LABEL}"

gcloud compute firewall-rules describe "${RIG_LABEL}-cluster-internal" --project="${PROJECT_ID}" >/dev/null 2>&1 || \
  gcloud compute firewall-rules create "${RIG_LABEL}-cluster-internal" \
    --project="${PROJECT_ID}" \
    --network="${NETWORK_NAME}" \
    --direction=INGRESS \
    --action=ALLOW \
    --rules="tcp:${API_PORT},tcp:${RAFT_PORT},udp:${GOSSIP_PORT},udp:${WIREGUARD_PORT},icmp" \
    --source-ranges="${NETWORK_CIDR}" \
    --target-tags="${RIG_LABEL}"

create_server() {
  local name="$1"
  if gcloud compute instances describe "${name}" --project="${PROJECT_ID}" --zone="${ZONE}" >/dev/null 2>&1; then
    log "instance ${name} already exists, reusing it"
    return
  fi

  local args=(
    compute instances create "${name}"
    --project="${PROJECT_ID}"
    --zone="${ZONE}"
    --machine-type="${SERVER_MACHINE_TYPE}"
    --boot-disk-size="${SERVER_DISK_GB}GB"
    --network="${NETWORK_NAME}"
    --subnet="${SUBNET_NAME}"
    --image-project="${CPU_IMAGE_PROJECT}"
    --image-family="${CPU_IMAGE_FAMILY}"
    --tags="${RIG_LABEL}"
    --labels="yoq-rig=${RIG_LABEL},yoq-role=server"
  )

  if [ "${USE_SPOT_SERVERS}" = "true" ]; then
    args+=(--provisioning-model=SPOT --instance-termination-action=DELETE)
  fi

  gcloud "${args[@]}"
}

create_agent() {
  local name="$1"
  if gcloud compute instances describe "${name}" --project="${PROJECT_ID}" --zone="${ZONE}" >/dev/null 2>&1; then
    log "instance ${name} already exists, reusing it"
    return
  fi

  local args=(
    compute instances create "${name}"
    --project="${PROJECT_ID}"
    --zone="${ZONE}"
    --machine-type="${AGENT_MACHINE_TYPE}"
    --boot-disk-size="${AGENT_DISK_GB}GB"
    --network="${NETWORK_NAME}"
    --subnet="${SUBNET_NAME}"
    --image-project="${AGENT_IMAGE_PROJECT}"
    --image-family="${AGENT_IMAGE_FAMILY}"
    --tags="${RIG_LABEL}"
    --labels="yoq-rig=${RIG_LABEL},yoq-role=agent"
  )

  if [ "${USE_GPU_AGENTS}" = "true" ]; then
    args+=(--maintenance-policy=TERMINATE)
    args+=(--accelerator="type=${GPU_TYPE},count=${GPU_COUNT_PER_AGENT}")
  fi

  if [ "${USE_GPU_AGENTS}" = "true" ] && [ "${USE_SPOT_GPU}" = "true" ]; then
    args+=(--provisioning-model=SPOT --instance-termination-action=DELETE)
  fi

  gcloud "${args[@]}"
}

log "creating server nodes"
create_server "${SERVER_1_NAME}"
create_server "${SERVER_2_NAME}"
create_server "${SERVER_3_NAME}"

log "creating GPU agent nodes"
create_agent "${AGENT_1_NAME}"
create_agent "${AGENT_2_NAME}"

for instance in \
  "${SERVER_1_NAME}" "${SERVER_2_NAME}" "${SERVER_3_NAME}" \
  "${AGENT_1_NAME}" "${AGENT_2_NAME}"; do
  log "waiting for SSH readiness on ${instance}"
  wait_for_ssh "${instance}" || die "instance ${instance} never became SSH-ready"
done

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

CLUSTER_JOIN_TOKEN="${CLUSTER_JOIN_TOKEN:-$(openssl rand -hex 32)}"
API_TOKEN="${API_TOKEN:-$(openssl rand -hex 32)}"

save_state_file
ln -sfn "${STATE_FILE}" "${STATE_ROOT}/current"

log "cluster inventory written to ${STATE_FILE}"
log "server API endpoint: ${SERVER_1_EXTERNAL_IP}:${API_PORT}"
