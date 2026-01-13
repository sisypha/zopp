---
sidebar_position: 2
title: workspace
description: Manage workspaces - create and list team workspaces.
---

# workspace

Manage workspaces. A workspace is the top-level container for your team's projects and secrets.

```bash
zopp workspace <COMMAND>
```

## Commands

| Command | Description |
|---------|-------------|
| `list` | List all workspaces you have access to |
| `create` | Create a new workspace |
| `grant-principal-access` | Grant a service principal access to a workspace |

---

## workspace list

List all workspaces you have access to.

```bash
zopp workspace list
```

### Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Print help |

### Example

```bash
$ zopp workspace list
NAME        ROLE
mycompany   admin
acme-corp   member
```

---

## workspace create

Create a new workspace. This generates a new Workspace KEK (Key Encryption Key) that is wrapped for your principal.

```bash
zopp workspace create <NAME>
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `NAME` | Yes | Name for the new workspace |

### Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Print help |

### Example

```bash
$ zopp workspace create mycompany
Workspace "mycompany" created successfully
```

---

## workspace grant-principal-access

Grant an existing service principal access to a workspace. This wraps the workspace KEK for the service principal's public key.

```bash
zopp workspace grant-principal-access -w <WORKSPACE> -p <PRINCIPAL>
```

### Options

| Option | Required | Description |
|--------|----------|-------------|
| `-w, --workspace <WORKSPACE>` | Yes | Workspace name |
| `-p, --principal <PRINCIPAL>` | Yes | Principal ID to grant access to |
| `-h, --help` | No | Print help |

### Example

```bash
$ zopp workspace grant-principal-access -w mycompany -p 550e8400-e29b-41d4-a716-446655440000
Access granted to principal 550e8400-e29b-41d4-a716-446655440000
```
