#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
YOQ_BIN="${YOQ_BIN:-$ROOT_DIR/zig-out/bin/yoq}"
MANIFEST="${MANIFEST:-$ROOT_DIR/examples/http-routing/manifest.toml}"
API_HOST="${API_HOST:-127.0.0.1}"
API_PORT="${API_PORT:-7700}"
PROXY_HOST="${PROXY_HOST:-127.0.0.1}"
PROXY_PORT="${PROXY_PORT:-17080}"

if [[ -n "${YOQ_SMOKE_DIR:-}" ]]; then
  SMOKE_DIR="${YOQ_SMOKE_DIR}"
  mkdir -p "$SMOKE_DIR"
else
  SMOKE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/yoq-http-routing-smoke.XXXXXX")"
fi

TEST_HOME="${YOQ_SMOKE_HOME:-$SMOKE_DIR/home}"
LOG_DIR="$SMOKE_DIR/logs"
mkdir -p "$TEST_HOME/.config" "$TEST_HOME/.cache" "$LOG_DIR"

export HOME="$TEST_HOME"
export XDG_DATA_HOME="$HOME/.local/share"
export XDG_CONFIG_HOME="$HOME/.config"
export XDG_CACHE_HOME="$HOME/.cache"

SERVER_PID=""
SERVER_LOG=""

log() {
  printf '== %s ==\n' "$1"
}

die() {
  printf '%s\n' "$1" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

cleanup() {
  set +e
  "$YOQ_BIN" down -f "$MANIFEST" >/dev/null 2>&1 || true
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" >/dev/null 2>&1; then
    kill "$SERVER_PID" >/dev/null 2>&1 || true
    wait "$SERVER_PID" >/dev/null 2>&1 || true
  fi
  printf 'artifacts kept at %s\n' "$SMOKE_DIR"
}

trap cleanup EXIT

api_status() {
  curl -fsS --max-time 3 "http://${API_HOST}:${API_PORT}/v1/status?mode=service_discovery"
}

api_metrics() {
  curl -fsS --max-time 3 "http://${API_HOST}:${API_PORT}/v1/metrics?format=prometheus"
}

route_body() {
  local host="$1"
  local path="$2"
  curl -fsS --max-time 5 -H "Host: ${host}" "http://${PROXY_HOST}:${PROXY_PORT}${path}"
}

wait_for() {
  local description="$1"
  shift
  local tries=0
  while [[ "$tries" -lt 60 ]]; do
    if "$@" >/dev/null 2>&1; then
      return 0
    fi
    tries=$((tries + 1))
    sleep 1
  done
  die "timed out waiting for ${description}"
}

server_ready() {
  api_status | jq -e \
    --argjson port "$PROXY_PORT" \
    '.listener.enabled == true and
     .listener.running == true and
     .listener.port == $port and
     .l7_proxy.enabled == true and
     .control_plane.enabled == true' >/dev/null
}

server_stopped() {
  ! curl -fsS --max-time 2 "http://${API_HOST}:${API_PORT}/health" >/dev/null 2>&1
}

routing_ready() {
  local root_body api_body docs_body
  root_body="$(route_body demo.local / 2>/dev/null || true)"
  api_body="$(route_body demo.local /api/get 2>/dev/null || true)"
  docs_body="$(route_body docs.demo.local / 2>/dev/null || true)"
  [[ "$root_body" == *"gateway route"* ]] || return 1
  [[ "$api_body" == *"api route"* ]] || return 1
  [[ "$docs_body" == *"docs route"* ]] || return 1
}

start_server() {
  SERVER_LOG="$LOG_DIR/serve-$(date +%H%M%S).log"
  "$YOQ_BIN" serve \
    --port "$API_PORT" \
    --http-proxy-bind "$PROXY_HOST" \
    --http-proxy-port "$PROXY_PORT" \
    >"$SERVER_LOG" 2>&1 &
  SERVER_PID=$!
  wait_for "API server readiness" server_ready
}

stop_server() {
  [[ -n "$SERVER_PID" ]] || return 0
  if kill -0 "$SERVER_PID" >/dev/null 2>&1; then
    kill "$SERVER_PID"
    wait "$SERVER_PID" >/dev/null 2>&1 || true
  fi
  SERVER_PID=""
  wait_for "API server shutdown" server_stopped
}

require_cmd curl
require_cmd jq

[[ -x "$YOQ_BIN" ]] || die "missing yoq binary at $YOQ_BIN; run 'zig build' first or set YOQ_BIN"
[[ -f "$MANIFEST" ]] || die "missing manifest at $MANIFEST"

cd "$ROOT_DIR"

log "validating manifest"
"$YOQ_BIN" validate -f "$MANIFEST"

log "starting API server and routing listener"
start_server

log "deploying HTTP routing example"
"$YOQ_BIN" up -f "$MANIFEST"
wait_for "initial routed traffic" routing_ready

log "capturing pre-restart discovery status"
api_status > "$SMOKE_DIR/status-before-restart.json"
jq -e \
  '.l7_proxy.running == true and
   .l7_proxy.routes >= 4 and
   .listener.running == true and
   .control_plane.running == true' \
  "$SMOKE_DIR/status-before-restart.json" >/dev/null

log "restarting API server"
stop_server
start_server

log "verifying route and listener recovery"
wait_for "post-restart routed traffic" routing_ready
api_status > "$SMOKE_DIR/status-after-restart.json"
api_metrics > "$SMOKE_DIR/metrics-after-restart.prom"

jq -e \
  '.l7_proxy.running == true and
   .l7_proxy.routes >= 4 and
   .listener.running == true and
   .listener.accepted_connections_total >= 1 and
   .control_plane.running == true' \
  "$SMOKE_DIR/status-after-restart.json" >/dev/null

grep -Fq 'yoq_service_discovery_mode{mode="canonical"} 1' "$SMOKE_DIR/metrics-after-restart.prom"
grep -Fq 'yoq_service_l7_proxy_listener_running 1' "$SMOKE_DIR/metrics-after-restart.prom"

log "HTTP routing recovery smoke passed"
