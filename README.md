# rbac-terminal-access

![Audit](https://img.shields.io/badge/audit%3A%20PASS-brightgreen) ![License](https://img.shields.io/badge/license-MIT-blue) ![OpenClaw](https://img.shields.io/badge/OpenClaw-skill-orange)

> Automates role-based access control for AI agent terminal operations with user-defined permissions.

## Features

- Define role-based permissions for terminal commands
- Enforce access control via CLI and agent integration
- Log access violations for auditing
- Support permission inheritance and custom levels

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

## Configuration

- Default permissions loaded from `scripts/permissions.json`
- CLI allows dynamic role and permission updates
- Audit log written to STDERR for transparency

## GitHub

Source code: [github.com/NeoSkillFactory/rbac-terminal-access](https://github.com/NeoSkillFactory/rbac-terminal-access)

**Price suggestion:** $79 USD

## License

MIT © NeoSkillFactory
