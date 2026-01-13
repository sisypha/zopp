---
sidebar_position: 4
title: environment
description: Manage environments within a project.
---

# environment

Manage environments within a project. Environments separate your secrets by deployment stage (development, staging, production, etc.).

```bash
zopp environment <COMMAND>
```

## Commands

| Command | Description |
|---------|-------------|
| `list` | List environments in a project |
| `create` | Create a new environment |
| `get` | Get environment details |
| `delete` | Delete an environment |

---

## environment list

List all environments in a project.

```bash
zopp environment list -w <WORKSPACE> -p <PROJECT>
```

### Options

| Option | Required | Description |
|--------|----------|-------------|
| `-w, --workspace <WORKSPACE>` | Yes | Workspace name |
| `-p, --project <PROJECT>` | Yes | Project name |
| `-h, --help` | No | Print help |

### Example

```bash
$ zopp environment list -w mycompany -p backend
NAME         SECRETS
development  12
staging      12
production   15
```

---

## environment create

Create a new environment. This generates a new DEK (Data Encryption Key) for the environment, wrapped with the workspace KEK.

```bash
zopp environment create -w <WORKSPACE> -p <PROJECT> <NAME>
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `NAME` | Yes | Name for the new environment |

### Options

| Option | Required | Description |
|--------|----------|-------------|
| `-w, --workspace <WORKSPACE>` | Yes | Workspace name |
| `-p, --project <PROJECT>` | Yes | Project name |
| `-h, --help` | No | Print help |

### Example

```bash
$ zopp environment create -w mycompany -p backend development
Environment "development" created
```

---

## environment get

Get details about a specific environment.

```bash
zopp environment get -w <WORKSPACE> -p <PROJECT> <NAME>
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `NAME` | Yes | Environment name |

### Options

| Option | Required | Description |
|--------|----------|-------------|
| `-w, --workspace <WORKSPACE>` | Yes | Workspace name |
| `-p, --project <PROJECT>` | Yes | Project name |
| `-h, --help` | No | Print help |

---

## environment delete

Delete an environment and all its secrets.

```bash
zopp environment delete -w <WORKSPACE> -p <PROJECT> <NAME>
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `NAME` | Yes | Environment name to delete |

### Options

| Option | Required | Description |
|--------|----------|-------------|
| `-w, --workspace <WORKSPACE>` | Yes | Workspace name |
| `-p, --project <PROJECT>` | Yes | Project name |
| `-h, --help` | No | Print help |

:::warning
This permanently deletes the environment and all its secrets. This action cannot be undone.
:::
