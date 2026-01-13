---
sidebar_position: 10
title: sync
description: Sync secrets to external systems like Kubernetes.
---

# sync

Sync secrets from zopp to external systems. Currently supports Kubernetes Secrets.

```bash
zopp sync <COMMAND>
```

## Commands

| Command | Description |
|---------|-------------|
| `k8s` | Sync secrets to a Kubernetes Secret |

---

## sync k8s

Sync secrets from a zopp environment to a Kubernetes Secret. Creates the Secret if it doesn't exist, or updates it if it does.

```bash
zopp sync k8s [OPTIONS] --namespace <NAMESPACE> --secret <SECRET>
```

### Options

| Option | Required | Description |
|--------|----------|-------------|
| `--namespace <NAMESPACE>` | Yes | Kubernetes namespace |
| `--secret <SECRET>` | Yes | Kubernetes Secret name to create/update |
| `-w, --workspace <WORKSPACE>` | No | Workspace name (defaults from zopp.toml) |
| `-p, --project <PROJECT>` | No | Project name (defaults from zopp.toml) |
| `-e, --environment <ENVIRONMENT>` | No | Environment name (defaults from zopp.toml) |
| `--kubeconfig <PATH>` | No | Path to kubeconfig file (default: ~/.kube/config) |
| `--context <CONTEXT>` | No | Kubernetes context to use |
| `--force` | No | Force sync even if Secret exists and not managed by zopp |
| `--dry-run` | No | Show what would be synced without applying |
| `-h, --help` | No | Print help |

### Examples

```bash
# Sync development secrets to Kubernetes
zopp sync k8s \
  -w mycompany -p backend -e development \
  --namespace default \
  --secret backend-secrets

# Dry run to preview changes
zopp sync k8s \
  --namespace production \
  --secret api-secrets \
  --dry-run

# Use specific kubeconfig and context
zopp sync k8s \
  --namespace staging \
  --secret app-secrets \
  --kubeconfig ~/.kube/staging-config \
  --context staging-cluster

# Force overwrite existing Secret
zopp sync k8s \
  --namespace default \
  --secret legacy-secrets \
  --force
```

### How It Works

1. Fetches all secrets from the specified zopp environment
2. Decrypts them client-side
3. Creates or updates a Kubernetes Secret with the decrypted values
4. Adds labels to track that the Secret is managed by zopp

### Labels Added

The synced Kubernetes Secret will have these labels:

```yaml
metadata:
  labels:
    app.kubernetes.io/managed-by: zopp
    zopp.dev/workspace: mycompany
    zopp.dev/project: backend
    zopp.dev/environment: development
```

:::tip
For continuous synchronization, consider using the [zopp Kubernetes Operator](/guides/kubernetes-operator) which watches for changes and keeps secrets in sync automatically.
:::
