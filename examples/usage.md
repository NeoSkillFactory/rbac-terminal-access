# RBAC Terminal Access — Usage Examples

## Example 1: Setting up a CI/CD role

```bash
# Create the role
python3 scripts/rbac-cli.py add-role cicd "CI/CD pipeline commands"

# Grant specific commands
python3 scripts/rbac-cli.py grant cicd docker
python3 scripts/rbac-cli.py grant cicd kubectl
python3 scripts/rbac-cli.py grant cicd helm

# Inherit basic read permissions
python3 scripts/rbac-cli.py inherit cicd reader

# Verify
python3 scripts/rbac-cli.py check cicd docker    # => allowed
python3 scripts/rbac-cli.py check cicd rm         # => denied
```

## Example 2: Checking permissions in a script

```bash
#!/usr/bin/env bash
ROLE="${AGENT_ROLE:-restricted}"
COMMAND="$1"

result=$(bash scripts/rbac.sh check "$ROLE" "$COMMAND" 2>/dev/null)
if [[ "$result" == "allowed" ]]; then
  eval "$COMMAND"
else
  echo "Access denied: role '$ROLE' cannot run '$COMMAND'"
  exit 1
fi
```

## Example 3: Auditing access decisions

All access decisions are logged to STDERR with timestamps:

```
[rbac 2026-03-08T14:30:00] ALLOWED: Role 'developer' can execute 'git'
[rbac 2026-03-08T14:30:01] DENIED: Role 'reader' cannot execute 'rm'
```

Capture audit logs:

```bash
bash scripts/rbac.sh check developer git 2>>rbac_audit.log
```

## Example 4: Listing effective permissions

```bash
# Show all permissions for developer (includes inherited from reader)
bash scripts/rbac.sh list-perms developer
# Output: cat, git, grep, head, ls, make, node, npm, tail
```
