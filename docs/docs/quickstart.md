---
sidebar_position: 2
title: Quickstart
description: Get up and running with zopp in 5 minutes.
---

# Quickstart

This guide will get you from zero to managing secrets in about 5 minutes.

## Prerequisites

- A running zopp server (or use `localhost:50051` for local development)
- An invite token from your server admin

:::tip
Don't have a server yet? Check out the [self-hosting guide](/zopp/self-hosting) to set one up, or run `cargo run --bin zopp-server serve` locally.
:::

## Install the CLI

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

<Tabs>
  <TabItem value="script" label="Install Script" default>

```bash
curl -fsSL https://raw.githubusercontent.com/faiscadev/zopp/main/install.sh | sh
```

  </TabItem>
  <TabItem value="cargo" label="Cargo">

```bash
cargo install --git https://github.com/faiscadev/zopp --package zopp-cli
```

  </TabItem>
  <TabItem value="docker" label="Docker">

```bash
docker pull ghcr.io/faiscadev/zopp-cli:latest
alias zopp='docker run --rm -v ~/.zopp:/home/zopp/.zopp ghcr.io/faiscadev/zopp-cli:latest'
```

  </TabItem>
</Tabs>

## Set Up Your First Workspace

### 1. Join the server

Use the invite token from your admin to register:

```bash
zopp join <invite-token> your@email.com
```

This creates your principal (device identity) with Ed25519 and X25519 keypairs.

### 2. Create a workspace

A workspace is your team's container for projects and secrets:

```bash
zopp workspace create mycompany
```

### 3. Create a project and environment

Projects organize your applications, environments separate dev/staging/prod:

```bash
zopp project create backend -w mycompany
zopp environment create development -w mycompany -p backend
```

### 4. Set up project defaults

Create a `zopp.toml` in your project directory to avoid typing flags every time:

```toml
[defaults]
workspace = "mycompany"
project = "backend"
environment = "development"
```

## Manage Secrets

Now you're ready to store and retrieve secrets:

```bash
# Set a secret
zopp secret set DATABASE_URL "postgresql://user:password@localhost/mydb"

# Get a secret
zopp secret get DATABASE_URL
# Output: postgresql://user:password@localhost/mydb

# List all secrets
zopp secret list
# Output:
# DATABASE_URL
```

## Run Commands with Secrets

Inject all secrets from your environment as environment variables:

```bash
# Run any command with secrets injected
zopp run -- npm start

# Or run a one-off command
zopp run -- printenv DATABASE_URL
```

## Export and Import

Work with `.env` files for compatibility with existing tools:

```bash
# Export secrets to .env
zopp secret export -o .env

# Import secrets from .env
zopp secret import -i .env
```

## Next Steps

You've got the basics down! Here's where to go next:

- [Core Concepts](/zopp/guides/core-concepts) - Understand workspaces, projects, environments, and the key hierarchy
- [Team Collaboration](/zopp/guides/team-collaboration) - Invite team members and manage permissions
- [CI/CD Integration](/zopp/guides/ci-cd) - Use service principals in your pipelines
- [Kubernetes](/zopp/guides/kubernetes-operator) - Sync secrets to Kubernetes clusters
- [CLI Reference](/zopp/reference/cli) - Full documentation of all commands
