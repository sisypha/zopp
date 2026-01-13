---
sidebar_position: 9
title: group
description: Manage user groups for easier permission management.
---

# group

Manage user groups. Groups make it easier to manage permissions for multiple users at once.

```bash
zopp group <COMMAND>
```

## Commands

### Group Management
| Command | Description |
|---------|-------------|
| `create` | Create a new group |
| `list` | List groups in a workspace |
| `delete` | Delete a group |
| `update` | Update group name or description |

### Membership
| Command | Description |
|---------|-------------|
| `add-member` | Add a user to a group |
| `remove-member` | Remove a user from a group |
| `list-members` | List members of a group |

### Workspace Permissions
| Command | Description |
|---------|-------------|
| `set-permission` | Set workspace permission for a group |
| `get-permission` | Get workspace permission for a group |
| `remove-permission` | Remove workspace permission for a group |
| `list-permissions` | List all group permissions on a workspace |

### Project Permissions
| Command | Description |
|---------|-------------|
| `set-project-permission` | Set project permission for a group |
| `get-project-permission` | Get project permission for a group |
| `remove-project-permission` | Remove project permission for a group |
| `list-project-permissions` | List group permissions on a project |

### Environment Permissions
| Command | Description |
|---------|-------------|
| `set-env-permission` | Set environment permission for a group |
| `get-env-permission` | Get environment permission for a group |
| `remove-env-permission` | Remove environment permission for a group |
| `list-env-permissions` | List group permissions on an environment |

---

## Group Management

### group create

Create a new group in a workspace.

```bash
zopp group create -w <WORKSPACE> <NAME> [DESCRIPTION]
```

#### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `NAME` | Yes | Group name |
| `DESCRIPTION` | No | Group description |

#### Options

| Option | Required | Description |
|--------|----------|-------------|
| `-w, --workspace <WORKSPACE>` | Yes | Workspace name |

#### Example

```bash
zopp group create -w mycompany developers "Backend development team"
```

### group list

List all groups in a workspace.

```bash
zopp group list -w <WORKSPACE>
```

### group delete

Delete a group.

```bash
zopp group delete -w <WORKSPACE> <NAME>
```

### group update

Update a group's name or description.

```bash
zopp group update -w <WORKSPACE> <NAME> [--name <NEW_NAME>] [--description <DESC>]
```

---

## Membership Management

### group add-member

Add a user to a group.

```bash
zopp group add-member -w <WORKSPACE> -g <GROUP> --email <EMAIL>
```

#### Options

| Option | Required | Description |
|--------|----------|-------------|
| `-w, --workspace <WORKSPACE>` | Yes | Workspace name |
| `-g, --group <GROUP>` | Yes | Group name |
| `--email <EMAIL>` | Yes | User email to add |

#### Example

```bash
zopp group add-member -w mycompany -g developers --email alice@example.com
```

### group remove-member

Remove a user from a group.

```bash
zopp group remove-member -w <WORKSPACE> -g <GROUP> --email <EMAIL>
```

### group list-members

List all members of a group.

```bash
zopp group list-members -w <WORKSPACE> -g <GROUP>
```

---

## Group Permissions

### group set-permission

Set workspace-level permission for a group.

```bash
zopp group set-permission -w <WORKSPACE> -g <GROUP> -r <ROLE>
```

#### Options

| Option | Required | Description |
|--------|----------|-------------|
| `-w, --workspace <WORKSPACE>` | Yes | Workspace name |
| `-g, --group <GROUP>` | Yes | Group name |
| `-r, --role <ROLE>` | Yes | Permission role: `read`, `write`, or `admin` |

#### Example

```bash
# Give developers write access to the workspace
zopp group set-permission -w mycompany -g developers -r write
```

### group set-project-permission

Set project-level permission for a group.

```bash
zopp group set-project-permission -w <WORKSPACE> --project <PROJECT> -g <GROUP> -r <ROLE>
```

### group set-env-permission

Set environment-level permission for a group.

```bash
zopp group set-env-permission -w <WORKSPACE> --project <PROJECT> -e <ENV> -g <GROUP> -r <ROLE>
```

#### Example

```bash
# Give developers write access to development, read access to production
zopp group set-env-permission -w mycompany --project backend -e development -g developers -r write
zopp group set-env-permission -w mycompany --project backend -e production -g developers -r read
```
