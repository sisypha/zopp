---
sidebar_position: 6
title: principal
description: Manage device identities and service principals.
---

# principal

Manage principals (device identities and service principals). A principal represents a device or service that can authenticate and access secrets.

```bash
zopp principal <COMMAND>
```

## Commands

| Command | Description |
|---------|-------------|
| `list` | List all your principals |
| `current` | Show the currently active principal |
| `create` | Create a new principal |
| `use` | Switch to a different principal |
| `rename` | Rename a principal |
| `delete` | Delete a principal |
| `service-list` | List service principals in a workspace |
| `workspace-remove` | Remove a principal from a workspace |
| `revoke-all` | Revoke all permissions for a principal |

---

## principal list

List all principals associated with your user.

```bash
zopp principal list
```

### Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Print help |

### Example

```bash
$ zopp principal list
NAME          TYPE      CURRENT
macbook-pro   device    *
linux-server  device
ci-runner     service
```

---

## principal current

Show the currently active principal.

```bash
zopp principal current
```

### Example

```bash
$ zopp principal current
Name: macbook-pro
Type: device
ID: 550e8400-e29b-41d4-a716-446655440000
```

---

## principal create

Create a new principal. Can be a device principal (tied to your user) or a service principal (standalone, for CI/CD).

```bash
zopp principal create [OPTIONS] <NAME>
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `NAME` | Yes | Name for the new principal |

### Options

| Option | Required | Description |
|--------|----------|-------------|
| `--service` | No | Create as service principal (no user association) |
| `-w, --workspace <WORKSPACE>` | No* | Workspace to add service principal to (*required with `--service`) |
| `-h, --help` | No | Print help |

### Examples

```bash
# Create a device principal
zopp principal create work-laptop

# Create a service principal for CI/CD
zopp principal create --service -w mycompany github-actions
```

---

## principal use

Switch to a different principal as your default.

```bash
zopp principal use <NAME>
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `NAME` | Yes | Principal name to switch to |

### Example

```bash
$ zopp principal use work-laptop
Switched to principal "work-laptop"
```

---

## principal rename

Rename an existing principal.

```bash
zopp principal rename <OLD_NAME> <NEW_NAME>
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `OLD_NAME` | Yes | Current principal name |
| `NEW_NAME` | Yes | New principal name |

---

## principal delete

Delete a principal. This revokes all access for that principal.

```bash
zopp principal delete <NAME>
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `NAME` | Yes | Principal name to delete |

:::warning
Deleting a principal permanently revokes its access to all workspaces. This cannot be undone.
:::

---

## principal service-list

List all service principals in a workspace.

```bash
zopp principal service-list -w <WORKSPACE>
```

### Options

| Option | Required | Description |
|--------|----------|-------------|
| `-w, --workspace <WORKSPACE>` | Yes | Workspace name |
| `-h, --help` | No | Print help |

---

## principal workspace-remove

Remove a principal from a workspace. This revokes all their permissions and removes their wrapped KEK.

```bash
zopp principal workspace-remove -w <WORKSPACE> -p <PRINCIPAL>
```

### Options

| Option | Required | Description |
|--------|----------|-------------|
| `-w, --workspace <WORKSPACE>` | Yes | Workspace name |
| `-p, --principal <PRINCIPAL>` | Yes | Principal ID to remove |
| `-h, --help` | No | Print help |

---

## principal revoke-all

Revoke all permissions for a principal in a workspace (workspace, project, and environment level). The principal remains a workspace member but has no permission roles. Use `workspace-remove` to completely remove a principal from a workspace.

```bash
zopp principal revoke-all -w <WORKSPACE> -p <PRINCIPAL>
```

### Options

| Option | Required | Description |
|--------|----------|-------------|
| `-w, --workspace <WORKSPACE>` | Yes | Workspace name |
| `-p, --principal <PRINCIPAL>` | Yes | Principal ID |
| `-h, --help` | No | Print help |
