#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUST_CLI_DIR="$ROOT_DIR/rust-cli"

BIN_NAME="${BIN_NAME:-saharoctl}"
RUN_LIVE="${RUN_LIVE:-0}"
BASE_URL="${BASE_URL:-}"

log() {
  printf '[smoke] %s\n' "$*"
}

fail() {
  printf '[smoke][fail] %s\n' "$*" >&2
  exit 1
}

assert_contains() {
  local haystack="$1"
  local needle="$2"
  if ! grep -Fq "$needle" <<<"$haystack"; then
    fail "expected output to contain: $needle"
  fi
}

run_help_checks() {
  log "building rust cli"
  (cd "$RUST_CLI_DIR" && cargo build >/dev/null)

  local root_help
  root_help="$("$RUST_CLI_DIR/target/debug/$BIN_NAME" --help)"
  assert_contains "$root_help" "portal"
  assert_contains "$root_help" "update"
  assert_contains "$root_help" "reconcile"

  local get_help
  get_help="$("$RUST_CLI_DIR/target/debug/$BIN_NAME" get --help)"
  assert_contains "$get_help" "service-events"
  assert_contains "$get_help" "service-state"
  assert_contains "$get_help" "service-known"

  local describe_help
  describe_help="$("$RUST_CLI_DIR/target/debug/$BIN_NAME" describe --help)"
  assert_contains "$describe_help" "service-drift"

  local delete_help
  delete_help="$("$RUST_CLI_DIR/target/debug/$BIN_NAME" delete --help)"
  assert_contains "$delete_help" "jobs"
  assert_contains "$delete_help" "host"

  local logs_help
  logs_help="$("$RUST_CLI_DIR/target/debug/$BIN_NAME" logs --help)"
  assert_contains "$logs_help" "api"
  assert_contains "$logs_help" "runtime"
  assert_contains "$logs_help" "node"

  local update_help
  update_help="$("$RUST_CLI_DIR/target/debug/$BIN_NAME" update --help)"
  assert_contains "$update_help" "nodes"
  assert_contains "$update_help" "service"
  assert_contains "$update_help" "cli"

  local portal_help
  portal_help="$("$RUST_CLI_DIR/target/debug/$BIN_NAME" portal --help)"
  assert_contains "$portal_help" "auth"
  assert_contains "$portal_help" "profile"
  assert_contains "$portal_help" "telemetry"
  assert_contains "$portal_help" "logout"

  log "help-surface checks passed"
}

run_live_checks() {
  if [[ "$RUN_LIVE" != "1" ]]; then
    log "RUN_LIVE=0, skipping live api checks"
    return 0
  fi

  if [[ -z "$BASE_URL" ]]; then
    fail "live mode requires BASE_URL, example: RUN_LIVE=1 BASE_URL=http://127.0.0.1:8010 $0"
  fi

  local ctl="$RUST_CLI_DIR/target/debug/$BIN_NAME"
  local common=(--base-url "$BASE_URL")

  log "running live checks against $BASE_URL"

  "$ctl" health --json >/dev/null
  "$ctl" get nodes "${common[@]}" --json >/dev/null
  "$ctl" get jobs "${common[@]}" --json >/dev/null
  "$ctl" get services "${common[@]}" --json >/dev/null
  "$ctl" get users "${common[@]}" --json >/dev/null
  "$ctl" get grants "${common[@]}" --json >/dev/null
  "$ctl" get invites "${common[@]}" --json >/dev/null
  "$ctl" get releases --json >/dev/null
  "$ctl" update cli "${common[@]}" --check-only >/dev/null || true
  "$ctl" update host "${common[@]}" --json >/dev/null || true
  "$ctl" update nodes "${common[@]}" --all --json >/dev/null || true
  "$ctl" portal profile >/dev/null || true

  local node_id
  node_id="$("$ctl" get nodes "${common[@]}" --json | \
    sed -n 's/.*"id":[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -n1)"
  if [[ -n "$node_id" ]]; then
    "$ctl" get node "$node_id" "${common[@]}" --json >/dev/null
    "$ctl" describe node "$node_id" "${common[@]}" --json >/dev/null
    "$ctl" logs node "$node_id" "${common[@]}" --json >/dev/null || true
    "$ctl" logs runtime "$node_id" "${common[@]}" --json >/dev/null || true
  else
    log "no nodes found, skipping node-specific checks"
  fi

  log "live checks finished"
}

main() {
  run_help_checks
  run_live_checks
  log "smoke completed"
}

main "$@"
