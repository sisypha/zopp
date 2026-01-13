---
sidebar_position: 1
title: Overview
description: Complete reference for all zopp CLI commands.
---

# Overview

The zopp CLI is the primary interface for managing secrets. All encryption happens client-side, so your plaintext secrets never leave your machine.

## Global Options

These options are available for all commands:

| Option | Environment Variable | Description |
|--------|---------------------|-------------|
| `--server <URL>` | `ZOPP_SERVER` | Server address (default: `http://127.0.0.1:50051`) |
| `--tls-ca-cert <PATH>` | `ZOPP_TLS_CA_CERT` | Path to CA certificate for TLS |
| `-h, --help` | | Show help for any command |

## Commands

### Getting Started
| Command | Description |
|---------|-------------|
| [`join`](join) | Register with a server or accept a workspace invite |
| [`run`](run) | Run a command with secrets injected as environment variables |

### Resource Management
| Command | Description |
|---------|-------------|
| [`workspace`](workspace) | Create and list workspaces |
| [`project`](project) | Manage projects within a workspace |
| [`environment`](environment) | Manage environments within a project |
| [`secret`](secret) | Store, retrieve, and manage encrypted secrets |

### Access Control
| Command | Description |
|---------|-------------|
| [`principal`](principal) | Manage device identities and service principals |
| [`permission`](permission) | Manage RBAC permissions |
| [`group`](group) | Manage user groups |
| [`invite`](invite) | Create and manage workspace invitations |

### Operations
| Command | Description |
|---------|-------------|
| [`sync`](sync) | Sync secrets to external systems (Kubernetes) |
| [`diff`](diff) | Compare secrets with external systems |
| [`audit`](audit) | View audit logs (admin only) |

## Configuration File

Create a `zopp.toml` in your project directory to set defaults:

```toml
[defaults]
workspace = "mycompany"
project = "api"
environment = "development"
```

With this configuration, you can omit the `-w`, `-p`, `-e` flags:

```bash
# These are equivalent:
zopp secret get API_KEY -w mycompany -p api -e development
zopp secret get API_KEY
```

See [Configuration Reference](/reference/configuration) for all options.

## Quick Examples

```bash
# Join a server
zopp join inv_abc123... you@example.com

# Create resources
zopp workspace create mycompany
zopp project create -w mycompany backend
zopp environment create -w mycompany -p backend development

# Manage secrets
zopp secret set DATABASE_URL "postgresql://..."
zopp secret get DATABASE_URL
zopp secret list

# Run with secrets
zopp run -- npm start

# Export/import
zopp secret export -o .env
zopp secret import -i .env

# Team collaboration
zopp invite create -w mycompany
zopp permission user-set -w mycompany --email teammate@example.com -r write
```
