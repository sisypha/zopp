# Zopp Kubernetes Operator Design

## Overview

The Zopp Kubernetes Operator automatically syncs secrets from Zopp to Kubernetes Secrets, eliminating the need for manual `zopp sync k8s` commands.

## Architecture

### Components

1. **Custom Resource Definition (CRD)**: `ZoppSecretSync`
   - Defines which zopp environment to sync to which K8s Secret
   - Specifies sync interval, workspace, project, environment
   - Stores connection details to zopp server

2. **Operator Controller**
   - Watches `ZoppSecretSync` resources
   - Reconciles K8s Secrets with zopp state
   - Runs on configurable interval (default: 5 minutes)
   - Handles error states and retries

3. **Secret Manager**
   - Reuses existing crypto/grpc code from CLI
   - Fetches and decrypts secrets from zopp
   - Creates/updates K8s Secrets with proper labels/annotations

### Custom Resource Definition

```yaml
apiVersion: zopp.dev/v1alpha1
kind: ZoppSecretSync
metadata:
  name: my-app-secrets
  namespace: my-app
spec:
  # Zopp connection
  server: https://zopp.example.com
  workspace: acme
  project: web-app
  environment: production

  # Principal authentication (references a K8s Secret)
  principalSecretRef:
    name: zopp-principal
    namespace: zopp-system

  # Target K8s Secret
  targetSecret:
    name: app-secrets
    namespace: my-app

  # Sync configuration
  syncInterval: 5m
  suspend: false  # Can pause syncing

status:
  lastSyncTime: "2025-01-15T10:30:00Z"
  lastSyncStatus: Success
  secretCount: 12
  conditions:
    - type: Ready
      status: "True"
      lastTransitionTime: "2025-01-15T10:30:00Z"
```

### Principal Authentication

The operator needs a zopp principal to authenticate. Store principal credentials in a K8s Secret:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: zopp-principal
  namespace: zopp-system
type: Opaque
stringData:
  id: "principal-uuid"
  name: "k8s-operator"
  private_key: "ed25519-private-key-hex"
  public_key: "ed25519-public-key-hex"
  x25519_private_key: "x25519-private-key-hex"
  x25519_public_key: "x25519-public-key-hex"
```

### Reconciliation Loop

1. **Watch** `ZoppSecretSync` resources
2. For each resource:
   - Check if suspended
   - Check if sync interval elapsed
   - Load principal credentials from referenced Secret
   - Connect to zopp server
   - Fetch and decrypt secrets
   - Compare with existing K8s Secret
   - Create or update K8s Secret if changed
   - Update status with sync time and result
3. Requeue for next sync interval

### Error Handling

- **Connection failures**: Exponential backoff, update status
- **Authentication failures**: Mark as error, don't retry until spec changes
- **Missing principal secret**: Mark as error, wait for secret to appear
- **K8s API failures**: Retry with backoff

### Security Considerations

- Principal secret should be tightly controlled (RBAC)
- Operator runs in dedicated namespace (`zopp-system`)
- Uses service account with minimal permissions:
  - Read `ZoppSecretSync` resources
  - Read principal Secret
  - Create/update target Secrets in specified namespaces
- No access to other Secrets

## Implementation Plan

### Phase 1: Core Operator
1. Create CRD definition
2. Create operator binary (`apps/zopp-operator`)
3. Implement basic reconciliation loop using `kube-rs`
4. Reuse crypto/grpc code from CLI
5. Basic status reporting

### Phase 2: Advanced Features
1. Support multiple principals (per-sync principal)
2. Drift detection and alerts
3. Metrics and observability (Prometheus)
4. Helm chart for easy deployment
5. E2E tests

### Phase 3: Extended Sync
1. Support for AWS Secrets Manager
2. Support for HashiCorp Vault
3. Support for GCP Secret Manager

## Dependencies

Reuse existing:
- `kube` and `k8s-openapi` (already in workspace)
- `zopp-crypto`, `zopp-proto` crates
- crypto.rs and grpc.rs helpers from CLI

New:
- `kube-runtime` for controller framework
- `futures` for async streams
- `tokio-util` for interval timing

## Deployment

```bash
# Apply CRD
kubectl apply -f deploy/crds/zoppsecretsync.yaml

# Create namespace
kubectl create namespace zopp-system

# Create principal secret
kubectl apply -f deploy/principal-secret.yaml

# Deploy operator
kubectl apply -f deploy/operator.yaml

# Create a sync resource
kubectl apply -f examples/sync-example.yaml
```

## Comparison with CLI

| Feature | CLI (`zopp sync k8s`) | Operator |
|---------|----------------------|----------|
| Trigger | Manual command | Automatic on interval |
| Auth | User's local principal | Service principal in K8s |
| Drift detection | Manual `zopp diff k8s` | Automatic reconciliation |
| Multi-environment | Run multiple commands | Multiple `ZoppSecretSync` resources |
| Deployment | Ad-hoc from laptop | Runs in-cluster |

## Migration Path

1. Existing users continue using CLI for one-off syncs
2. For production deployments, switch to operator for automation
3. Both can coexist (CLI for emergency manual syncs)
