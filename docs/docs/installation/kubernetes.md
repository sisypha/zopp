---
sidebar_position: 4
title: Kubernetes Installation
description: Deploy zopp to Kubernetes using Helm.
---

# Kubernetes Installation

The zopp Helm chart deploys both the server and the Kubernetes operator, which automatically syncs zopp secrets to Kubernetes Secrets.

## Prerequisites

- Kubernetes 1.24+
- Helm 3.8+
- `kubectl` configured for your cluster

## Quick Install

### 1. Install the Helm chart

```bash
helm install zopp oci://ghcr.io/faiscadev/charts/zopp --version 0.1.0
```

This deploys:
- zopp server with SQLite storage
- zopp operator watching all namespaces
- Required RBAC resources

### 2. Create a server invite

```bash
kubectl exec -it deploy/zopp-server -- zopp-server invite create --expires-hours 48
```

### 3. Join the server

On your local machine with the CLI installed:

```bash
zopp --server http://localhost:50051 join <token> your@email.com
```

Port-forward if needed:
```bash
kubectl port-forward svc/zopp-server 50051:50051
```

## Components

### Server

The zopp gRPC server stores encrypted secrets and handles authentication.

```yaml
server:
  enabled: true
  replicaCount: 1

  database:
    type: sqlite  # or postgres
    sqlite:
      path: /data/zopp.db
      persistence:
        enabled: true
        size: 1Gi
```

### Operator

The operator watches for `ZoppSecret` custom resources and syncs them to Kubernetes Secrets.

```yaml
operator:
  enabled: true
  watchNamespace: ""  # Empty = watch all namespaces

  credentials:
    existingSecret: zopp-operator-credentials
```

:::note
The operator requires credentials to authenticate with the zopp server. See [setting up operator credentials](#operator-credentials) below.
:::

## Common Configurations

### PostgreSQL Backend

For production, use PostgreSQL instead of SQLite:

```yaml
# values-postgres.yaml
server:
  database:
    type: postgres
    postgres:
      existingSecret: zopp-db-credentials
      existingSecretKey: DATABASE_URL
```

Create the secret:

```bash
kubectl create secret generic zopp-db-credentials \
  --from-literal=DATABASE_URL="postgres://user:pass@postgres.example.com/zopp"
```

Install:

```bash
helm install zopp oci://ghcr.io/faiscadev/charts/zopp \
  --version 0.1.0 \
  -f values-postgres.yaml
```

### TLS Encryption

Enable TLS for the server:

```yaml
# values-tls.yaml
server:
  tls:
    enabled: true
    existingSecret: zopp-server-tls  # Contains tls.crt and tls.key
```

Create the TLS secret:

```bash
kubectl create secret tls zopp-server-tls \
  --cert=server.crt \
  --key=server.key
```

### Operator-Only Mode

If you have a central zopp server and just need the operator:

```yaml
# values-operator-only.yaml
server:
  enabled: false

operator:
  enabled: true
  server:
    address: "zopp.example.com:50051"
    tls:
      enabled: true
      existingSecret: zopp-server-ca  # Contains ca.crt

  credentials:
    existingSecret: zopp-operator-credentials
```

## Operator Credentials

The operator needs credentials to authenticate with the zopp server:

### 1. Create operator credentials locally

```bash
# Join the server as a service principal
zopp join <invite-token> operator@yourcluster

# Or create a dedicated service principal
zopp principal create k8s-operator --service -w myworkspace
```

### 2. Create the Kubernetes secret

```bash
kubectl create secret generic zopp-operator-credentials \
  --from-file=config.json=$HOME/.zopp/config.json
```

### 3. Reference in Helm values

```yaml
operator:
  credentials:
    existingSecret: zopp-operator-credentials
```

## Using ZoppSecret Resources

Once the operator is running, create `ZoppSecret` resources to sync secrets:

```yaml
apiVersion: zopp.dev/v1alpha1
kind: ZoppSecret
metadata:
  name: my-app-secrets
  namespace: default
spec:
  workspace: mycompany
  project: backend
  environment: production
  secretName: my-app-env  # Name of the K8s Secret to create
```

The operator will:
1. Fetch secrets from zopp
2. Create/update the Kubernetes Secret
3. Keep it in sync with zopp

## Values Reference

See the [Helm Chart README](https://github.com/faiscadev/zopp/tree/main/charts/zopp) for a complete list of configuration options.

### Key Values

| Parameter | Description | Default |
|-----------|-------------|---------|
| `server.enabled` | Deploy the server | `true` |
| `server.database.type` | `sqlite` or `postgres` | `sqlite` |
| `server.tls.enabled` | Enable TLS | `false` |
| `operator.enabled` | Deploy the operator | `true` |
| `operator.watchNamespace` | Namespace to watch | `""` (all) |
| `rbac.clusterWide` | Use ClusterRole | `true` |

## Upgrading

```bash
helm upgrade zopp oci://ghcr.io/faiscadev/charts/zopp --version 0.1.1
```

## Uninstalling

```bash
helm uninstall zopp
```

:::caution
PersistentVolumeClaims are not deleted automatically. Remove manually if needed:
```bash
kubectl delete pvc -l app.kubernetes.io/instance=zopp
```
:::

## Next Steps

- [Kubernetes Operator Guide](/guides/kubernetes-operator) - Detailed operator usage
- [Self-Hosting Guide](/self-hosting) - Production deployment considerations
- [TLS Configuration](/self-hosting/tls) - Secure your deployment
