---
sidebar_position: 3
title: project
description: Manage projects within a workspace.
---

# project

Manage projects within a workspace. Projects organize your applications and services.

```bash
zopp project <COMMAND>
```

## Commands

| Command | Description |
|---------|-------------|
| `list` | List projects in a workspace |
| `create` | Create a new project |
| `get` | Get project details |
| `delete` | Delete a project |

---

## project list

List all projects in a workspace.

```bash
zopp project list -w <WORKSPACE>
```

### Options

| Option | Required | Description |
|--------|----------|-------------|
| `-w, --workspace <WORKSPACE>` | Yes | Workspace name |
| `-h, --help` | No | Print help |

### Example

```bash
$ zopp project list -w mycompany
NAME      ENVIRONMENTS
backend   3
frontend  2
mobile    1
```

---

## project create

Create a new project in a workspace.

```bash
zopp project create -w <WORKSPACE> <NAME>
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `NAME` | Yes | Name for the new project |

### Options

| Option | Required | Description |
|--------|----------|-------------|
| `-w, --workspace <WORKSPACE>` | Yes | Workspace name |
| `-h, --help` | No | Print help |

### Example

```bash
$ zopp project create -w mycompany backend
Project "backend" created in workspace "mycompany"
```

---

## project get

Get details about a specific project.

```bash
zopp project get -w <WORKSPACE> <NAME>
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `NAME` | Yes | Project name |

### Options

| Option | Required | Description |
|--------|----------|-------------|
| `-w, --workspace <WORKSPACE>` | Yes | Workspace name |
| `-h, --help` | No | Print help |

---

## project delete

Delete a project and all its environments and secrets.

```bash
zopp project delete -w <WORKSPACE> <NAME>
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `NAME` | Yes | Project name to delete |

### Options

| Option | Required | Description |
|--------|----------|-------------|
| `-w, --workspace <WORKSPACE>` | Yes | Workspace name |
| `-h, --help` | No | Print help |

:::warning
This permanently deletes the project and all associated environments and secrets. This action cannot be undone.
:::
