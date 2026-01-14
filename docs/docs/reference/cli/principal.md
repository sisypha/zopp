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
| `export` | Export a principal to an encrypted file |
| `import` | Import a principal from an encrypted file |
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

## principal export

Export a principal to an encrypted file for transfer to another device.

```bash
zopp principal export <NAME> [-o <OUTPUT>]
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `NAME` | Yes | Principal name to export |

### Options

| Option | Required | Description |
|--------|----------|-------------|
| `-o, --output <FILE>` | No | Output file path (prints to stdout if not specified) |
| `-h, --help` | No | Print help |

### Example

```bash
# Export to a file
$ zopp principal export laptop -o principal.enc
Enter passphrase to encrypt export: ********
Confirm passphrase: ********
✓ Principal 'laptop' exported to principal.enc
  Import on another device with: zopp principal import -i <file>
```

:::tip
The export is encrypted with a passphrase using Argon2id key derivation and XChaCha20-Poly1305. Use a strong passphrase and transfer the file securely.
:::

---

## principal import

Import a principal from an encrypted file.

```bash
zopp principal import [-i <INPUT>]
```

### Options

| Option | Required | Description |
|--------|----------|-------------|
| `-i, --input <FILE>` | No | Input file path (reads from stdin if not specified) |
| `-h, --help` | No | Print help |

### Example

```bash
# Import from a file
$ zopp principal import -i principal.enc
Enter passphrase to decrypt: ********
✓ Principal 'laptop' imported successfully
  Server URL from export: https://zopp.example.com:50051
  Use with: zopp --server https://zopp.example.com:50051 workspace list
```

:::note
If a principal with the same name already exists, the imported principal will be renamed with an `-imported` suffix.
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
