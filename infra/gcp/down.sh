#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

require_state

for instance in \
  "${SERVER_1_NAME}" "${SERVER_2_NAME}" "${SERVER_3_NAME}" \
  "${AGENT_1_NAME}" "${AGENT_2_NAME}"; do
  if gcloud compute instances describe "${instance}" --project="${PROJECT_ID}" --zone="${ZONE}" >/dev/null 2>&1; then
    log "deleting instance ${instance}"
    gcloud compute instances delete "${instance}" \
      --project="${PROJECT_ID}" \
      --zone="${ZONE}" \
      --quiet
  fi
done

for rule in "${RIG_LABEL}-ssh-api" "${RIG_LABEL}-cluster-internal"; do
  if gcloud compute firewall-rules describe "${rule}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    log "deleting firewall rule ${rule}"
    gcloud compute firewall-rules delete "${rule}" --project="${PROJECT_ID}" --quiet
  fi
done

if gcloud compute networks subnets describe "${SUBNET_NAME}" --project="${PROJECT_ID}" --region="${REGION}" >/dev/null 2>&1; then
  log "deleting subnet ${SUBNET_NAME}"
  gcloud compute networks subnets delete "${SUBNET_NAME}" \
    --project="${PROJECT_ID}" \
    --region="${REGION}" \
    --quiet
fi

if gcloud compute networks describe "${NETWORK_NAME}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  log "deleting network ${NETWORK_NAME}"
  gcloud compute networks delete "${NETWORK_NAME}" \
    --project="${PROJECT_ID}" \
    --quiet
fi

rm -rf "${STATE_DIR}"
log "teardown complete"
