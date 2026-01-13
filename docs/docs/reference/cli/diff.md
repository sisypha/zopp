---
sidebar_position: 11
title: diff
description: Compare secrets between zopp and external systems.
---

# diff

Show differences between zopp secrets and external systems. Useful for auditing and verifying sync status.

```bash
zopp diff <COMMAND>
```

## Commands

| Command | Description |
|---------|-------------|
| `k8s` | Show diff between zopp and a Kubernetes Secret |

---

## diff k8s

Compare secrets in a zopp environment with a Kubernetes Secret. Shows which keys are added, removed, or changed.

```bash
zopp diff k8s [OPTIONS] --namespace <NAMESPACE> --secret <SECRET>
```

### Options

| Option | Required | Description |
|--------|----------|-------------|
| `--namespace <NAMESPACE>` | Yes | Kubernetes namespace |
| `--secret <SECRET>` | Yes | Kubernetes Secret name to compare |
| `-w, --workspace <WORKSPACE>` | No | Workspace name (defaults from zopp.toml) |
| `-p, --project <PROJECT>` | No | Project name (defaults from zopp.toml) |
| `-e, --environment <ENVIRONMENT>` | No | Environment name (defaults from zopp.toml) |
| `--kubeconfig <PATH>` | No | Path to kubeconfig file (default: ~/.kube/config) |
| `--context <CONTEXT>` | No | Kubernetes context to use |
| `-h, --help` | No | Print help |

### Example Output

```bash
$ zopp diff k8s --namespace default --secret backend-secrets

Comparing zopp (mycompany/backend/development) with k8s (default/backend-secrets)

+ API_KEY           (only in zopp)
- OLD_SECRET        (only in k8s)
~ DATABASE_URL      (values differ)

Summary: 1 added, 1 removed, 1 changed
```

### Legend

| Symbol | Meaning |
|--------|---------|
| `+` | Key exists in zopp but not in Kubernetes |
| `-` | Key exists in Kubernetes but not in zopp |
| `~` | Key exists in both but values differ |

### Examples

```bash
# Basic diff
zopp diff k8s --namespace default --secret app-secrets

# Diff against production cluster
zopp diff k8s \
  -e production \
  --namespace production \
  --secret api-secrets \
  --context prod-cluster

# Use with zopp.toml defaults
zopp diff k8s --namespace staging --secret backend-secrets
```

:::tip
Run `zopp diff k8s` before `zopp sync k8s` to preview what changes will be applied.
:::
