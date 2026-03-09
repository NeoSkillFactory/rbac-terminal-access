#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(dirname "$SCRIPT_DIR")"
RBAC_SH="$SKILL_DIR/scripts/rbac.sh"
RBAC_CLI="$SKILL_DIR/scripts/rbac-cli.py"
TEST_PERMS="$SCRIPT_DIR/test_permissions.json"

PASS=0
FAIL=0

setup() {
  cat > "$TEST_PERMS" <<'JSON'
{
  "roles": {
    "admin": {
      "description": "Full access",
      "permissions": ["*"],
      "inherits": []
    },
    "developer": {
      "description": "Dev commands",
      "permissions": ["git", "npm", "node", "make"],
      "inherits": ["reader"]
    },
    "reader": {
      "description": "Read-only",
      "permissions": ["ls", "cat", "grep", "head", "tail"],
      "inherits": []
    },
    "restricted": {
      "description": "Minimal access",
      "permissions": ["echo", "pwd"],
      "inherits": []
    }
  }
}
JSON
  export RBAC_PERMISSIONS_FILE="$TEST_PERMS"
}

teardown() {
  rm -f "$TEST_PERMS"
}

assert_eq() {
  local test_name="$1" expected="$2" actual="$3"
  if [[ "$expected" == "$actual" ]]; then
    echo "  PASS: $test_name"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: $test_name (expected='$expected', actual='$actual')"
    FAIL=$((FAIL + 1))
  fi
}

assert_exit_code() {
  local test_name="$1" expected="$2" actual="$3"
  if [[ "$expected" == "$actual" ]]; then
    echo "  PASS: $test_name"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: $test_name (expected exit=$expected, got exit=$actual)"
    FAIL=$((FAIL + 1))
  fi
}

# --- rbac.sh tests ---

test_admin_wildcard() {
  echo "Test: Admin wildcard access"
  local result
  result=$(bash "$RBAC_SH" check admin rm 2>/dev/null) || true
  assert_eq "admin can run rm" "allowed" "$result"

  result=$(bash "$RBAC_SH" check admin anything 2>/dev/null) || true
  assert_eq "admin can run anything" "allowed" "$result"
}

test_reader_allowed() {
  echo "Test: Reader allowed commands"
  local result
  result=$(bash "$RBAC_SH" check reader ls 2>/dev/null) || true
  assert_eq "reader can ls" "allowed" "$result"

  result=$(bash "$RBAC_SH" check reader cat 2>/dev/null) || true
  assert_eq "reader can cat" "allowed" "$result"
}

test_reader_denied() {
  echo "Test: Reader denied commands"
  local result exit_code
  result=$(bash "$RBAC_SH" check reader rm 2>/dev/null) && exit_code=0 || exit_code=$?
  assert_eq "reader cannot rm" "denied" "$result"
  assert_exit_code "reader rm exits 1" "1" "$exit_code"
}

test_developer_inherited() {
  echo "Test: Developer inherits reader permissions"
  local result
  result=$(bash "$RBAC_SH" check developer ls 2>/dev/null) || true
  assert_eq "developer can ls (inherited)" "allowed" "$result"

  result=$(bash "$RBAC_SH" check developer git 2>/dev/null) || true
  assert_eq "developer can git (own)" "allowed" "$result"
}

test_developer_denied() {
  echo "Test: Developer denied unauthorized commands"
  local result exit_code
  result=$(bash "$RBAC_SH" check developer rm 2>/dev/null) && exit_code=0 || exit_code=$?
  assert_eq "developer cannot rm" "denied" "$result"
  assert_exit_code "developer rm exits 1" "1" "$exit_code"
}

test_restricted_minimal() {
  echo "Test: Restricted role minimal access"
  local result exit_code
  result=$(bash "$RBAC_SH" check restricted echo 2>/dev/null) || true
  assert_eq "restricted can echo" "allowed" "$result"

  result=$(bash "$RBAC_SH" check restricted ls 2>/dev/null) && exit_code=0 || exit_code=$?
  assert_eq "restricted cannot ls" "denied" "$result"
}

test_nonexistent_role() {
  echo "Test: Nonexistent role"
  local result exit_code
  result=$(bash "$RBAC_SH" check fakrole ls 2>/dev/null) && exit_code=0 || exit_code=$?
  assert_eq "nonexistent role denied" "denied" "$result"
  assert_exit_code "nonexistent role exits 1" "1" "$exit_code"
}

test_validate() {
  echo "Test: Validate permissions file"
  local result
  result=$(bash "$RBAC_SH" validate 2>/dev/null)
  assert_eq "validate passes" "Permissions file is valid." "$result"
}

test_list_roles() {
  echo "Test: List roles"
  local result
  result=$(bash "$RBAC_SH" list-roles 2>/dev/null)
  echo "$result" | grep -q "admin" && assert_eq "list includes admin" "yes" "yes" || assert_eq "list includes admin" "yes" "no"
  echo "$result" | grep -q "reader" && assert_eq "list includes reader" "yes" "yes" || assert_eq "list includes reader" "yes" "no"
}

test_list_perms() {
  echo "Test: List permissions for developer"
  local result
  result=$(bash "$RBAC_SH" list-perms developer 2>/dev/null)
  echo "$result" | grep -q "git" && assert_eq "developer perms include git" "yes" "yes" || assert_eq "developer perms include git" "yes" "no"
  echo "$result" | grep -q "ls" && assert_eq "developer perms include ls (inherited)" "yes" "yes" || assert_eq "developer perms include ls (inherited)" "yes" "no"
}

# --- rbac-cli.py tests ---

test_cli_list_roles() {
  echo "Test: CLI list-roles"
  local result
  result=$(python3 "$RBAC_CLI" list-roles 2>/dev/null)
  echo "$result" | grep -q "admin" && assert_eq "cli list has admin" "yes" "yes" || assert_eq "cli list has admin" "yes" "no"
}

test_cli_add_remove_role() {
  echo "Test: CLI add-role and remove-role"
  python3 "$RBAC_CLI" add-role tester "Test role" >/dev/null 2>&1
  local result
  result=$(python3 "$RBAC_CLI" show tester 2>/dev/null)
  echo "$result" | grep -q "tester" && assert_eq "cli added tester" "yes" "yes" || assert_eq "cli added tester" "yes" "no"

  python3 "$RBAC_CLI" remove-role tester >/dev/null 2>&1
  local exit_code
  python3 "$RBAC_CLI" show tester >/dev/null 2>&1 && exit_code=0 || exit_code=$?
  assert_exit_code "cli removed tester" "1" "$exit_code"
}

test_cli_grant_revoke() {
  echo "Test: CLI grant and revoke"
  python3 "$RBAC_CLI" add-role tempuser "Temp" >/dev/null 2>&1
  python3 "$RBAC_CLI" grant tempuser docker >/dev/null 2>&1

  local result
  result=$(python3 "$RBAC_CLI" check tempuser docker 2>/dev/null) || true
  assert_eq "cli granted docker" "allowed" "$result"

  python3 "$RBAC_CLI" revoke tempuser docker >/dev/null 2>&1
  local exit_code
  result=$(python3 "$RBAC_CLI" check tempuser docker 2>/dev/null) && exit_code=0 || exit_code=$?
  assert_eq "cli revoked docker" "denied" "$result"

  python3 "$RBAC_CLI" remove-role tempuser >/dev/null 2>&1
}

test_cli_check() {
  echo "Test: CLI check command"
  local result
  result=$(python3 "$RBAC_CLI" check admin ls 2>/dev/null) || true
  assert_eq "cli check admin ls" "allowed" "$result"

  local exit_code
  result=$(python3 "$RBAC_CLI" check restricted rm 2>/dev/null) && exit_code=0 || exit_code=$?
  assert_eq "cli check restricted rm" "denied" "$result"
}

# --- Run all tests ---

main() {
  echo "=== RBAC Terminal Access Test Suite ==="
  echo ""
  setup

  trap teardown EXIT

  echo "--- rbac.sh tests ---"
  test_admin_wildcard
  test_reader_allowed
  test_reader_denied
  test_developer_inherited
  test_developer_denied
  test_restricted_minimal
  test_nonexistent_role
  test_validate
  test_list_roles
  test_list_perms

  echo ""
  echo "--- rbac-cli.py tests ---"
  test_cli_list_roles
  test_cli_add_remove_role
  test_cli_grant_revoke
  test_cli_check

  echo ""
  echo "=== Results: $PASS passed, $FAIL failed ==="

  if [[ $FAIL -gt 0 ]]; then
    exit 1
  fi
}

main "$@"
