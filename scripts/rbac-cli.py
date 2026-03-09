#!/usr/bin/env python3
"""CLI interface for managing RBAC policies for terminal access control."""

import json
import os
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_PERMISSIONS_FILE = SCRIPT_DIR / "permissions.json"
PERMISSIONS_FILE = Path(os.environ.get("RBAC_PERMISSIONS_FILE", str(DEFAULT_PERMISSIONS_FILE)))


def load_permissions():
    """Load the permissions file."""
    if not PERMISSIONS_FILE.exists():
        print(f"Error: Permissions file not found: {PERMISSIONS_FILE}", file=sys.stderr)
        sys.exit(1)
    try:
        with open(PERMISSIONS_FILE, "r") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in permissions file: {e}", file=sys.stderr)
        sys.exit(1)


def save_permissions(data):
    """Save the permissions file."""
    with open(PERMISSIONS_FILE, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def cmd_add_role(args):
    """Add a new role."""
    if len(args) < 1:
        print("Usage: rbac-cli.py add-role <role_name> [description]", file=sys.stderr)
        sys.exit(1)
    role_name = args[0]
    description = " ".join(args[1:]) if len(args) > 1 else f"Custom role: {role_name}"

    data = load_permissions()
    if role_name in data["roles"]:
        print(f"Error: Role '{role_name}' already exists", file=sys.stderr)
        sys.exit(1)

    data["roles"][role_name] = {
        "description": description,
        "permissions": [],
        "inherits": [],
    }
    save_permissions(data)
    print(f"Role '{role_name}' created.")


def cmd_remove_role(args):
    """Remove a role."""
    if len(args) < 1:
        print("Usage: rbac-cli.py remove-role <role_name>", file=sys.stderr)
        sys.exit(1)
    role_name = args[0]

    data = load_permissions()
    if role_name not in data["roles"]:
        print(f"Error: Role '{role_name}' not found", file=sys.stderr)
        sys.exit(1)

    # Check if any role inherits from this one
    for name, role in data["roles"].items():
        if role_name in role.get("inherits", []):
            print(f"Error: Cannot remove role '{role_name}' — inherited by '{name}'", file=sys.stderr)
            sys.exit(1)

    del data["roles"][role_name]
    save_permissions(data)
    print(f"Role '{role_name}' removed.")


def cmd_grant(args):
    """Grant a permission to a role."""
    if len(args) < 2:
        print("Usage: rbac-cli.py grant <role_name> <command>", file=sys.stderr)
        sys.exit(1)
    role_name, command = args[0], args[1]

    data = load_permissions()
    if role_name not in data["roles"]:
        print(f"Error: Role '{role_name}' not found", file=sys.stderr)
        sys.exit(1)

    perms = data["roles"][role_name]["permissions"]
    if command in perms:
        print(f"Permission '{command}' already granted to '{role_name}'.")
        return

    perms.append(command)
    save_permissions(data)
    print(f"Granted '{command}' to role '{role_name}'.")


def cmd_revoke(args):
    """Revoke a permission from a role."""
    if len(args) < 2:
        print("Usage: rbac-cli.py revoke <role_name> <command>", file=sys.stderr)
        sys.exit(1)
    role_name, command = args[0], args[1]

    data = load_permissions()
    if role_name not in data["roles"]:
        print(f"Error: Role '{role_name}' not found", file=sys.stderr)
        sys.exit(1)

    perms = data["roles"][role_name]["permissions"]
    if command not in perms:
        print(f"Permission '{command}' not found in role '{role_name}'.", file=sys.stderr)
        sys.exit(1)

    perms.remove(command)
    save_permissions(data)
    print(f"Revoked '{command}' from role '{role_name}'.")


def cmd_inherit(args):
    """Add role inheritance."""
    if len(args) < 2:
        print("Usage: rbac-cli.py inherit <child_role> <parent_role>", file=sys.stderr)
        sys.exit(1)
    child, parent = args[0], args[1]

    data = load_permissions()
    if child not in data["roles"]:
        print(f"Error: Role '{child}' not found", file=sys.stderr)
        sys.exit(1)
    if parent not in data["roles"]:
        print(f"Error: Role '{parent}' not found", file=sys.stderr)
        sys.exit(1)

    inherits = data["roles"][child]["inherits"]
    if parent in inherits:
        print(f"Role '{child}' already inherits from '{parent}'.")
        return

    inherits.append(parent)
    save_permissions(data)
    print(f"Role '{child}' now inherits from '{parent}'.")


def cmd_list_roles(_args):
    """List all roles."""
    data = load_permissions()
    for name, role in sorted(data["roles"].items()):
        desc = role.get("description", "")
        perms_count = len(role.get("permissions", []))
        inherits = role.get("inherits", [])
        inherit_str = f" (inherits: {', '.join(inherits)})" if inherits else ""
        print(f"  {name}: {desc} [{perms_count} permissions]{inherit_str}")


def cmd_check(args):
    """Check if a role can execute a command using rbac.sh."""
    if len(args) < 2:
        print("Usage: rbac-cli.py check <role_name> <command>", file=sys.stderr)
        sys.exit(1)
    role_name, command = args[0], args[1]

    rbac_sh = SCRIPT_DIR / "rbac.sh"
    if not rbac_sh.exists():
        print(f"Error: rbac.sh not found at {rbac_sh}", file=sys.stderr)
        sys.exit(1)

    env = os.environ.copy()
    env["RBAC_PERMISSIONS_FILE"] = str(PERMISSIONS_FILE)
    result = subprocess.run(
        ["bash", str(rbac_sh), "check", role_name, command],
        capture_output=True,
        text=True,
        env=env,
    )
    print(result.stdout.strip())
    if result.stderr:
        print(result.stderr.strip(), file=sys.stderr)
    sys.exit(result.returncode)


def cmd_show(args):
    """Show details of a specific role."""
    if len(args) < 1:
        print("Usage: rbac-cli.py show <role_name>", file=sys.stderr)
        sys.exit(1)
    role_name = args[0]

    data = load_permissions()
    if role_name not in data["roles"]:
        print(f"Error: Role '{role_name}' not found", file=sys.stderr)
        sys.exit(1)

    role = data["roles"][role_name]
    print(f"Role: {role_name}")
    print(f"Description: {role.get('description', '')}")
    print(f"Permissions: {', '.join(role.get('permissions', []))}")
    inherits = role.get("inherits", [])
    if inherits:
        print(f"Inherits from: {', '.join(inherits)}")


COMMANDS = {
    "add-role": cmd_add_role,
    "remove-role": cmd_remove_role,
    "grant": cmd_grant,
    "revoke": cmd_revoke,
    "inherit": cmd_inherit,
    "list-roles": cmd_list_roles,
    "check": cmd_check,
    "show": cmd_show,
}


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print("Usage: rbac-cli.py <command> [args...]")
        print()
        print("Commands:")
        print("  add-role <name> [desc]     Add a new role")
        print("  remove-role <name>         Remove a role")
        print("  grant <role> <command>     Grant permission to a role")
        print("  revoke <role> <command>    Revoke permission from a role")
        print("  inherit <child> <parent>   Add role inheritance")
        print("  list-roles                 List all roles")
        print("  check <role> <command>     Check permission for a command")
        print("  show <role>                Show role details")
        sys.exit(0 if len(sys.argv) >= 2 else 1)

    cmd = sys.argv[1]
    if cmd not in COMMANDS:
        print(f"Error: Unknown command '{cmd}'", file=sys.stderr)
        print(f"Available commands: {', '.join(sorted(COMMANDS.keys()))}", file=sys.stderr)
        sys.exit(1)

    COMMANDS[cmd](sys.argv[2:])


if __name__ == "__main__":
    main()
