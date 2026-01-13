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
| `--action <ACTION>` | No | Filter by action type |
| `--result <RESULT>` | No | Filter by result (success/denied) |
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

Audit logs (10 of 247 total):

ID:        550e8400-e29b-41d4-a716-446655440000
Timestamp: 2024-01-10T14:30:00Z
Action:    secret.read
Resource:  secret (backend/prod/DATABASE_URL)
Result:    success

ID:        550e8400-e29b-41d4-a716-446655440001
Timestamp: 2024-01-10T14:25:00Z
Action:    secret.write
Resource:  secret (backend/dev/API_KEY)
Result:    success
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

ID:           550e8400-e29b-41d4-a716-446655440000
Timestamp:    2024-01-10T14:30:00Z
Principal ID: 660e8400-e29b-41d4-a716-446655440000
User ID:      770e8400-e29b-41d4-a716-446655440000
Action:       secret.read
Resource:     secret (backend/production/DATABASE_URL)
Workspace:    880e8400-e29b-41d4-a716-446655440000
Project:      990e8400-e29b-41d4-a716-446655440000
Environment:  aa0e8400-e29b-41d4-a716-446655440000
Result:       success
Client IP:    192.168.1.100
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
| `--result <RESULT>` | No | Filter by result (success/denied) |

### Example

```bash
$ zopp audit count -w mycompany --action secret.read
Total audit log entries: 1247
```
