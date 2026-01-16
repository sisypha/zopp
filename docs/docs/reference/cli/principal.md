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
| `export` | Export a principal to the server for retrieval on another device |
| `import` | Import a principal from the server using a passphrase |
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
| `--export` | No | Export the principal immediately after creation for easy setup on another device |
| `-h, --help` | No | Print help |

### Examples

```bash
# Create a device principal
zopp principal create work-laptop

# Create a device principal and immediately export for setup on another device
zopp principal create new-laptop --export

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

## principal export

Export a principal to the server for retrieval on another device. A secure 6-word passphrase is generated from the EFF wordlist and displayed. The encrypted principal data is stored on the server for up to 24 hours and can only be retrieved once.

```bash
zopp principal export <NAME> [--expires-hours <HOURS>]
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `NAME` | Yes | Principal name to export |

### Options

| Option | Required | Description |
|--------|----------|-------------|
| `--expires-hours <HOURS>` | No | Expiration time in hours (default: 24) |
| `-h, --help` | No | Print help |

### Example

```bash
$ zopp principal export laptop

Principal 'laptop' export created successfully.

Export code:
    exp_a7k9m2x4

Passphrase (write this down):
    correct horse battery staple purple llama

This export expires in 24 hours.
After 3 failed passphrase attempts, the export is permanently deleted.

On your new device, run:
    zopp --server https://zopp.example.com:50051 principal import
```

:::tip
The passphrase provides approximately 77 bits of entropy (6 words from a 7776-word list). Write it down or copy it securely - it will only be shown once.
:::

:::info Security
- The export is encrypted with a key derived from the passphrase using Argon2id (64 MiB, 3 iterations)
- The export code (e.g., `exp_a7k9m2x4`) is used for lookup; the passphrase hash is used for server-side verification
- The server cannot decrypt your principal data without the passphrase
- Each export can only be retrieved once (consumed on import)
- Exports self-destruct after 3 failed passphrase attempts
:::

---

## principal import

Import a principal from the server using the export code and passphrase.

```bash
zopp principal import [-c CODE]
```

### Options

| Option | Required | Description |
|--------|----------|-------------|
| `-c`, `--code` | No | Export code (will prompt if not provided) |

### Example

```bash
# Interactive (recommended - prompts for code and passphrase securely)
$ zopp principal import
Enter export code: exp_a7k9m2x4
Enter passphrase: ************************************
Principal 'laptop' imported successfully.

You are now authenticated as:
  Email: alice@example.com
  Principal: laptop

Test with: zopp workspace list

# With export code provided
$ zopp principal import -c exp_a7k9m2x4
Enter passphrase: ************************************
Principal 'laptop' imported successfully.

# For automated/scripted usage, use env var (never pass passphrase on command line)
$ ZOPP_EXPORT_PASSPHRASE="correct horse battery staple purple llama" zopp principal import -c exp_a7k9m2x4
```

:::note
If a principal with the same name already exists locally, the imported principal will be renamed with an `-imported` suffix.
:::

:::warning One-time use
Each export can only be imported once. If you need to set up multiple devices, create a new export for each device.
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
