#!/usr/bin/env bash
set -euo pipefail

ROLE="${1:?usage: start-node.sh <server|agent> ...}"
shift

case "${ROLE}" in
  server)
    ID="${1:?server id required}"
    RAFT_PORT="${2:?raft port required}"
    API_PORT="${3:?api port required}"
    CLUSTER_JOIN_TOKEN="${4:?cluster join token required}"
    API_TOKEN="${5:?api token required}"
    shift 5
    PEERS="${*:-}"
    printf 'starting server %s with peers: %s\n' "${ID}" "${PEERS:-<none>}" >/var/log/yoq-start-node.log

    pkill -f "yoq init-server" || true
    if [ -n "${PEERS}" ]; then
      nohup env HOME=/root yoq init-server \
        --id "${ID}" \
        --port "${RAFT_PORT}" \
        --api-port "${API_PORT}" \
        --peers "${PEERS}" \
        --token "${CLUSTER_JOIN_TOKEN}" \
        --api-token "${API_TOKEN}" \
        >/var/log/yoq-server.log 2>&1 < /dev/null &
    else
      nohup env HOME=/root yoq init-server \
        --id "${ID}" \
        --port "${RAFT_PORT}" \
        --api-port "${API_PORT}" \
        --token "${CLUSTER_JOIN_TOKEN}" \
        --api-token "${API_TOKEN}" \
        >/var/log/yoq-server.log 2>&1 < /dev/null &
    fi
    ;;
  agent)
    SERVER_ADDR="${1:?server address required}"
    CLUSTER_JOIN_TOKEN="${2:?cluster join token required}"
    API_PORT="${3:?api port required}"

    pkill -f "yoq join" || true
    nohup env HOME=/root yoq join \
      "${SERVER_ADDR}" \
      --token "${CLUSTER_JOIN_TOKEN}" \
      --port "${API_PORT}" \
      --role agent \
      >/var/log/yoq-agent.log 2>&1 < /dev/null &
    ;;
  *)
    echo "usage: start-node.sh <server|agent> ..." >&2
    exit 1
    ;;
esac
