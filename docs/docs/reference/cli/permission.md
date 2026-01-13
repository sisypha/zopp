---
sidebar_position: 8
title: permission
description: Manage access control and RBAC permissions.
---

# permission

Manage role-based access control (RBAC) permissions. Permissions can be set at workspace, project, or environment level for principals, users, or groups.

```bash
zopp permission <COMMAND>
```

## Permission Levels

| Role | Description |
|------|-------------|
| `read` | Can read secrets |
| `write` | Can read and write secrets |
| `admin` | Full access including managing permissions |

## Commands Overview

### Principal Permissions
| Command | Description |
|---------|-------------|
| `set` | Set workspace permission for a principal |
| `get` | Get workspace permission for a principal |
| `list` | List all permissions on a workspace |
| `remove` | Remove workspace permission for a principal |
| `project-set` | Set project permission for a principal |
| `project-get` | Get project permission for a principal |
| `project-list` | List project permissions |
| `project-remove` | Remove project permission |
| `env-set` | Set environment permission for a principal |
| `env-get` | Get environment permission for a principal |
| `env-list` | List environment permissions |
| `env-remove` | Remove environment permission |

### User Permissions (by email)
| Command | Description |
|---------|-------------|
| `user-set` | Set workspace permission for a user |
| `user-get` | Get workspace permission for a user |
| `user-list` | List all user permissions on a workspace |
| `user-remove` | Remove workspace permission for a user |
| `user-project-set` | Set project permission for a user |
| `user-project-get` | Get project permission for a user |
| `user-project-list` | List user project permissions |
| `user-project-remove` | Remove project permission for a user |
| `user-env-set` | Set environment permission for a user |
| `user-env-get` | Get environment permission for a user |
| `user-env-list` | List user environment permissions |
| `user-env-remove` | Remove environment permission for a user |

### Utility
| Command | Description |
|---------|-------------|
| `effective` | Show aggregated effective permissions for a principal |

---

## Workspace Permissions

### permission set

Set workspace-level permission for a principal.

```bash
zopp permission set -w <WORKSPACE> -p <PRINCIPAL> -r <ROLE>
```

#### Options

| Option | Required | Description |
|--------|----------|-------------|
| `-w, --workspace <WORKSPACE>` | Yes | Workspace name |
| `-p, --principal <PRINCIPAL>` | Yes | Principal ID |
| `-r, --role <ROLE>` | Yes | Permission role: `read`, `write`, or `admin` |

#### Example

```bash
zopp permission set -w mycompany -p 550e8400-... -r write
```

### permission get

Get workspace permission for a principal.

```bash
zopp permission get -w <WORKSPACE> -p <PRINCIPAL>
```

### permission list

List all principal permissions on a workspace.

```bash
zopp permission list -w <WORKSPACE>
```

### permission remove

Remove workspace permission for a principal.

```bash
zopp permission remove -w <WORKSPACE> -p <PRINCIPAL>
```

---

## Project Permissions

### permission project-set

Set project-level permission for a principal.

```bash
zopp permission project-set -w <WORKSPACE> --project <PROJECT> -p <PRINCIPAL> -r <ROLE>
```

#### Options

| Option | Required | Description |
|--------|----------|-------------|
| `-w, --workspace <WORKSPACE>` | Yes | Workspace name |
| `--project <PROJECT>` | Yes | Project name |
| `-p, --principal <PRINCIPAL>` | Yes | Principal ID |
| `-r, --role <ROLE>` | Yes | Permission role |

### permission project-list

List all principal permissions on a project.

```bash
zopp permission project-list -w <WORKSPACE> --project <PROJECT>
```

---

## Environment Permissions

### permission env-set

Set environment-level permission for a principal.

```bash
zopp permission env-set -w <WORKSPACE> --project <PROJECT> -e <ENVIRONMENT> -p <PRINCIPAL> -r <ROLE>
```

#### Options

| Option | Required | Description |
|--------|----------|-------------|
| `-w, --workspace <WORKSPACE>` | Yes | Workspace name |
| `--project <PROJECT>` | Yes | Project name |
| `-e, --environment <ENVIRONMENT>` | Yes | Environment name |
| `-p, --principal <PRINCIPAL>` | Yes | Principal ID |
| `-r, --role <ROLE>` | Yes | Permission role |

---

## User Permissions

User permissions work the same as principal permissions but use email addresses instead of principal IDs.

### permission user-set

Set workspace permission for a user by email.

```bash
zopp permission user-set -w <WORKSPACE> --email <EMAIL> -r <ROLE>
```

#### Options

| Option | Required | Description |
|--------|----------|-------------|
| `-w, --workspace <WORKSPACE>` | Yes | Workspace name |
| `--email <EMAIL>` | Yes | User email address |
| `-r, --role <ROLE>` | Yes | Permission role |

#### Example

```bash
zopp permission user-set -w mycompany --email alice@example.com -r admin
```

---

## Effective Permissions

### permission effective

Show the aggregated effective permissions for a principal across all levels (workspace, projects, environments).

```bash
zopp permission effective -w <WORKSPACE> -p <PRINCIPAL>
```

#### Example

```bash
$ zopp permission effective -w mycompany -p 550e8400-...
SCOPE                           ROLE
workspace: mycompany            admin
project: backend                write (inherited)
  env: development              write (inherited)
  env: production               read (explicit)
project: frontend               write (inherited)
```
