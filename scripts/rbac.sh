#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PERMISSIONS_FILE="${RBAC_PERMISSIONS_FILE:-$SCRIPT_DIR/permissions.json}"

log() {
  echo "[rbac $(date '+%Y-%m-%dT%H:%M:%S')] $*" >&2
}

usage() {
  cat <<'USAGE'
Usage: rbac.sh <action> [arguments]

Actions:
  check <role> <command>   Check if a role has permission to run a command
  list-roles               List all defined roles
  list-perms <role>        List permissions for a role (including inherited)
  validate                 Validate the permissions.json file

Exit codes:
  0  Access allowed / success
  1  Access denied / error
USAGE
}

require_jq() {
  if ! command -v jq &>/dev/null; then
    log "ERROR: jq is required but not installed"
    exit 1
  fi
}

validate_permissions_file() {
  if [[ ! -f "$PERMISSIONS_FILE" ]]; then
    log "ERROR: Permissions file not found: $PERMISSIONS_FILE"
    exit 1
  fi
  if ! jq empty "$PERMISSIONS_FILE" 2>/dev/null; then
    log "ERROR: Invalid JSON in permissions file: $PERMISSIONS_FILE"
    exit 1
  fi
  if ! jq -e '.roles' "$PERMISSIONS_FILE" &>/dev/null; then
    log "ERROR: Missing 'roles' key in permissions file"
    exit 1
  fi
}

get_role_permissions() {
  local role="$1"
  local visited="$2"

  if echo "$visited" | grep -qw "$role"; then
    return
  fi
  visited="$visited $role"

  if ! jq -e ".roles[\"$role\"]" "$PERMISSIONS_FILE" &>/dev/null; then
    log "ERROR: Role '$role' not found"
    return
  fi

  jq -r ".roles[\"$role\"].permissions[]" "$PERMISSIONS_FILE" 2>/dev/null

  local inherits
  inherits=$(jq -r ".roles[\"$role\"].inherits[]?" "$PERMISSIONS_FILE" 2>/dev/null)
  for parent in $inherits; do
    get_role_permissions "$parent" "$visited"
  done
}

check_permission() {
  local role="$1"
  local command="$2"

  if ! jq -e ".roles[\"$role\"]" "$PERMISSIONS_FILE" &>/dev/null; then
    log "DENIED: Role '$role' does not exist"
    echo "denied"
    return 1
  fi

  local all_perms
  all_perms=$(get_role_permissions "$role" "" | sort -u)

  if echo "$all_perms" | grep -qx '\*'; then
    log "ALLOWED: Role '$role' has wildcard access for '$command'"
    echo "allowed"
    return 0
  fi

  local base_command
  base_command=$(basename "$command" | awk '{print $1}')

  if echo "$all_perms" | grep -qx "$base_command"; then
    log "ALLOWED: Role '$role' can execute '$base_command'"
    echo "allowed"
    return 0
  fi

  log "DENIED: Role '$role' cannot execute '$base_command'"
  echo "denied"
  return 1
}

list_roles() {
  jq -r '.roles | keys[]' "$PERMISSIONS_FILE"
}

list_perms() {
  local role="$1"
  if ! jq -e ".roles[\"$role\"]" "$PERMISSIONS_FILE" &>/dev/null; then
    log "ERROR: Role '$role' not found"
    exit 1
  fi
  get_role_permissions "$role" "" | sort -u
}

main() {
  if [[ $# -lt 1 ]]; then
    usage
    exit 1
  fi

  require_jq

  local action="$1"
  shift

  case "$action" in
    check)
      if [[ $# -lt 2 ]]; then
        log "ERROR: check requires <role> and <command>"
        usage
        exit 1
      fi
      validate_permissions_file
      check_permission "$1" "$2"
      ;;
    list-roles)
      validate_permissions_file
      list_roles
      ;;
    list-perms)
      if [[ $# -lt 1 ]]; then
        log "ERROR: list-perms requires <role>"
        usage
        exit 1
      fi
      validate_permissions_file
      list_perms "$1"
      ;;
    validate)
      validate_permissions_file
      echo "Permissions file is valid."
      ;;
    *)
      log "ERROR: Unknown action '$action'"
      usage
      exit 1
      ;;
  esac
}

main "$@"
