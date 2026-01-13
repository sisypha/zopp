---
sidebar_position: 12
title: audit
description: View audit logs for workspace activity.
---

# audit

View audit logs for workspace activity. Audit logs track all actions performed in a workspace for compliance and security monitoring.

```bash
zopp audit <COMMAND>
```

:::note
Audit log commands require admin permission on the workspace.
:::

## Commands

| Command | Description |
|---------|-------------|
| `list` | List audit log entries |
| `get` | Get details of a specific audit entry |
| `count` | Count audit log entries |

---

## audit list

List audit log entries for a workspace.

```bash
zopp audit list [OPTIONS] -w <WORKSPACE>
```

### Options

| Option | Required | Description |
|--------|----------|-------------|
| `-w, --workspace <WORKSPACE>` | Yes | Workspace name |
| `--limit <LIMIT>` | No | Maximum entries to return (default: 50) |
| `--offset <OFFSET>` | No | Number of entries to skip |
| `--action <ACTION>` | No | Filter by action type |
| `--principal <PRINCIPAL>` | No | Filter by principal ID |
| `--since <TIMESTAMP>` | No | Filter entries after this time |
| `--until <TIMESTAMP>` | No | Filter entries before this time |
| `-h, --help` | No | Print help |

### Action Types

| Action | Description |
|--------|-------------|
| `secret.read` | Secret was read |
| `secret.write` | Secret was created or updated |
| `secret.delete` | Secret was deleted |
| `principal.create` | Principal was created |
| `principal.delete` | Principal was deleted |
| `permission.grant` | Permission was granted |
| `permission.revoke` | Permission was revoked |
| `invite.create` | Invite was created |
| `invite.consume` | Invite was used |

### Example

```bash
$ zopp audit list -w mycompany --limit 10

TIMESTAMP            ACTION          PRINCIPAL      RESOURCE
2024-01-10 14:30:00  secret.read     alice@...      backend/prod/DATABASE_URL
2024-01-10 14:25:00  secret.write    bob@...        backend/dev/API_KEY
2024-01-10 14:20:00  permission.grant admin@...     user:charlie@...
```

---

## audit get

Get detailed information about a specific audit log entry.

```bash
zopp audit get -w <WORKSPACE> <ENTRY_ID>
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `ENTRY_ID` | Yes | Audit entry ID |

### Options

| Option | Required | Description |
|--------|----------|-------------|
| `-w, --workspace <WORKSPACE>` | Yes | Workspace name |

### Example

```bash
$ zopp audit get -w mycompany 550e8400-e29b-41d4-a716-446655440000

Entry ID: 550e8400-e29b-41d4-a716-446655440000
Timestamp: 2024-01-10T14:30:00Z
Action: secret.read
Principal: alice@example.com (550e8400-...)
Resource: backend/production/DATABASE_URL
IP Address: 192.168.1.100
User Agent: zopp-cli/1.0.0
```

---

## audit count

Count audit log entries matching criteria.

```bash
zopp audit count [OPTIONS] -w <WORKSPACE>
```

### Options

| Option | Required | Description |
|--------|----------|-------------|
| `-w, --workspace <WORKSPACE>` | Yes | Workspace name |
| `--action <ACTION>` | No | Filter by action type |
| `--principal <PRINCIPAL>` | No | Filter by principal ID |
| `--since <TIMESTAMP>` | No | Filter entries after this time |
| `--until <TIMESTAMP>` | No | Filter entries before this time |

### Example

```bash
$ zopp audit count -w mycompany --action secret.read --since 2024-01-01
Count: 1,247
```
