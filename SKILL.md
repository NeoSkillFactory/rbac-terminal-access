---
name: rbac-terminal-access
description: Automates role-based access control for AI agent terminal operations with user-defined permissions.
version: 1.0.0
triggers:
  - "Create a role-based access control system for terminal commands"
  - "Limit AI agent access to specific terminal operations"
  - "Set up permission-based terminal access controls"
  - "Implement RBAC for my OpenClaw agent"
  - "Restrict which commands my AI assistant can run"
  - "Create roles with different terminal access levels"
  - "Protect my system from unauthorized terminal commands"
---

# rbac-terminal-access

## One-sentence Description

Automates role-based access control for AI agent terminal operations with user-defined permissions.

## Core Capabilities

- Define role-based permissions for terminal commands
- Enforce access control via CLI and agent integration
- Log access violations for auditing
- Support permission inheritance and custom levels

## Implementation

- **Storage**: Permissions stored in `scripts/permissions.json`
- **Validation**: Access checks handled by `scripts/rbac.sh`
- **CLI**: Policy management via `scripts/rbac-cli.py`
- **Integration**: Invoked by OpenClaw agents during terminal operations

## Configuration

- Default permissions loaded from `scripts/permissions.json`
- CLI allows dynamic role and permission updates
- Audit log written to STDERR for transparency

## Usage

```bash
# Check if a role can execute a command
./scripts/rbac.sh check <role> <command>

# Manage roles via CLI
python3 scripts/rbac-cli.py add-role <role_name>
python3 scripts/rbac-cli.py grant <role_name> <command>
python3 scripts/rbac-cli.py revoke <role_name> <command>
python3 scripts/rbac-cli.py list-roles
python3 scripts/rbac-cli.py check <role_name> <command>
```
