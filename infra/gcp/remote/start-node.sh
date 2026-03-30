#!/usr/bin/env bash
set -euo pipefail

ROLE="${1:?usage: start-node.sh <server|server-restart|agent> ...}"
shift

start_server() {
  local preserve_data="$1"
  local id="${2:?server id required}"
  local raft_port="${3:?raft port required}"
  local api_port="${4:?api port required}"
  local http_proxy_port="${5:?http proxy port required}"
  local cluster_join_token="${6:?cluster join token required}"
  local api_token="${7:?api token required}"
  shift 7

  local peers=""
  if [ "$#" -gt 0 ]; then
    peers="$(IFS=,; printf '%s' "$*")"
  fi
  printf 'starting server %s with peers: %s\n' "${id}" "${peers:-<none>}" >/var/log/yoq-start-node.log

  pkill -f "yoq init-server" || true
  sleep 1
  if [ "${preserve_data}" != "true" ]; then
    rm -rf /root/.local/share/yoq/cluster
  fi

  if [ -n "${peers}" ]; then
    nohup env HOME=/root yoq init-server \
      --id "${id}" \
      --port "${raft_port}" \
      --api-port "${api_port}" \
      --http-proxy-bind 0.0.0.0 \
      --http-proxy-port "${http_proxy_port}" \
      --peers "${peers}" \
      --token "${cluster_join_token}" \
      --api-token "${api_token}" \
      >/var/log/yoq-server.log 2>&1 < /dev/null &
  else
    nohup env HOME=/root yoq init-server \
      --id "${id}" \
      --port "${raft_port}" \
      --api-port "${api_port}" \
      --http-proxy-bind 0.0.0.0 \
      --http-proxy-port "${http_proxy_port}" \
      --token "${cluster_join_token}" \
      --api-token "${api_token}" \
      >/var/log/yoq-server.log 2>&1 < /dev/null &
  fi
}

case "${ROLE}" in
  server)
    start_server false "$@"
    ;;
  server-restart)
    start_server true "$@"
    ;;
  agent)
    SERVER_ADDR="${1:?server address required}"
    CLUSTER_JOIN_TOKEN="${2:?cluster join token required}"
    API_PORT="${3:?api port required}"

    pkill -f "yoq join" || true
    sleep 1
    rm -rf /root/.local/share/yoq/cluster
    nohup env HOME=/root yoq join \
      "${SERVER_ADDR}" \
      --token "${CLUSTER_JOIN_TOKEN}" \
      --port "${API_PORT}" \
      --role agent \
      >/var/log/yoq-agent.log 2>&1 < /dev/null &
    ;;
  *)
    echo "usage: start-node.sh <server|server-restart|agent> ..." >&2
    exit 1
    ;;
esac
