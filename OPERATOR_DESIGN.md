# Zopp Kubernetes Operator Design

## Overview

The Zopp Kubernetes Operator automatically syncs secrets from Zopp to Kubernetes Secrets. It supports two modes of operation:

1. **Annotation-based** (simple): Annotate existing K8s Secrets to sync from Zopp
2. **CRD-based** (GitOps): Use `ZoppSecretSync` custom resources for declarative configuration

## Architecture

### Dual-Mode Sync

The operator runs both sync modes concurrently:

```
┌─────────────────────────────────────────────────────────────┐
│                     Zopp Operator                           │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────────┐     ┌──────────────────────────────┐ │
│  │ Annotation Mode  │     │        CRD Mode              │ │
│  │                  │     │                              │ │
│  │ Watches Secrets  │     │ Watches ZoppSecretSync CRs   │ │
│  │ with zopp.dev/*  │     │ Creates/updates target       │ │
│  │ annotations      │     │ Secrets                      │ │
│  └────────┬─────────┘     └──────────────┬───────────────┘ │
│           │                              │                  │
│           └──────────────┬───────────────┘                  │
│                          ▼                                  │
│                 ┌────────────────┐                          │
│                 │  Sync Engine   │                          │
│                 │ - gRPC client  │                          │
│                 │ - Crypto       │                          │
│                 │ - DEK cache    │                          │
│                 └────────────────┘                          │
└─────────────────────────────────────────────────────────────┘
```

### Sync Strategy

Both modes use a dual-sync strategy for reliability:

1. **Event Streaming (Primary)**: Real-time updates via gRPC `WatchSecrets` stream
   - Sub-second latency for secret changes
   - Automatic reconnection with exponential backoff

2. **Periodic Polling (Safeguard)**: Full resync every 60 seconds
   - Catches missed events during stream disconnections
   - Ensures eventual consistency

## Mode 1: Annotation-Based (Simple)

Annotate existing K8s Secrets to sync from Zopp:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-app-secrets
  namespace: default
  annotations:
    zopp.dev/sync: "true"
    zopp.dev/workspace: "acme"
    zopp.dev/project: "backend"
    zopp.dev/environment: "production"
type: Opaque
data: {}  # Operator will populate this
```

**Pros:**
- Quick setup - just annotate existing Secrets
- No new resource types to learn
- Works with existing tooling

**Cons:**
- Configuration mixed with the Secret itself
- No separate status reporting

## Mode 2: CRD-Based (GitOps)

Use `ZoppSecretSync` custom resources for declarative, GitOps-friendly configuration:

```yaml
apiVersion: zopp.dev/v1alpha1
kind: ZoppSecretSync
metadata:
  name: backend-production
  namespace: zopp-system
spec:
  source:
    workspace: acme
    project: backend
    environment: production
  target:
    secretName: app-secrets
    namespace: my-app          # Can be different from CRD namespace
    secretType: Opaque         # Optional, default: Opaque
    labels:                    # Optional: labels for the created Secret
      app: backend
    annotations:               # Optional: annotations for the created Secret
      description: "Backend secrets"
  syncIntervalSeconds: 60      # Optional, default: 60
  suspend: false               # Optional: pause syncing
status:
  lastSyncTime: "2025-01-15T10:30:00Z"
  lastSyncVersion: 42
  secretCount: 12
  observedGeneration: 1
  conditions:
    - type: Ready
      status: "True"
      reason: SyncSuccess
      message: "Synced 12 secrets"
      lastTransitionTime: "2025-01-15T10:30:00Z"
```

**Pros:**
- Declarative configuration separate from Secrets
- Rich status reporting with conditions
- Can create Secrets in different namespaces
- GitOps friendly - check CRDs into version control

**Cons:**
- Requires installing CRD
- Slightly more complex setup

## Principal Authentication

The operator authenticates with Zopp using a service principal. Credentials are provided via environment variables from a K8s Secret:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: zopp-operator-credentials
  namespace: zopp-system
type: Opaque
stringData:
  ZOPP_PRINCIPAL_ID: "uuid-of-principal"
  ZOPP_PRINCIPAL_NAME: "k8s-operator"
  ZOPP_PRIVATE_KEY: "ed25519-private-key-hex"
  ZOPP_PUBLIC_KEY: "ed25519-public-key-hex"
  ZOPP_X25519_PRIVATE_KEY: "x25519-private-key-hex"
  ZOPP_X25519_PUBLIC_KEY: "x25519-public-key-hex"
```

Create the service principal using the CLI:

```bash
# Create a service principal for the operator
zopp principal create --name k8s-operator --type service

# Export credentials for K8s
zopp principal export --name k8s-operator --format k8s-secret > credentials.yaml
kubectl apply -f credentials.yaml
```

## Deployment Reload

The operator can automatically restart Deployments when their secrets change. Opt-in by adding an annotation to your Deployment:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  annotations:
    zopp.dev/reload: "true"  # Enable automatic reload
spec:
  template:
    spec:
      containers:
      - name: app
        envFrom:
        - secretRef:
            name: app-secrets  # References a zopp-managed Secret
```

When the operator updates `app-secrets`, it will:
1. Find Deployments with `zopp.dev/reload: "true"`
2. Check if they reference the updated Secret
3. Trigger a rolling restart by patching `spec.template.metadata.annotations`

## RBAC Requirements

The operator needs the following permissions:

```yaml
rules:
# Core secrets management
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list", "watch", "create", "update", "patch"]

# ZoppSecretSync CRD (CRD mode only)
- apiGroups: ["zopp.dev"]
  resources: ["zoppsecretsyncs"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["zopp.dev"]
  resources: ["zoppsecretsyncs/status"]
  verbs: ["get", "update", "patch"]

# Deployment reload
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get", "list", "patch"]
```

## Deployment

### Using Helm

```bash
# Add the Zopp Helm repository
helm repo add zopp https://charts.zopp.dev

# Install with operator enabled
helm install zopp zopp/zopp \
  --set operator.enabled=true \
  --set operator.credentials.existingSecret=zopp-operator-credentials
```

### Manual Deployment

```bash
# Apply CRD (for CRD mode)
kubectl apply -f charts/zopp/crds/zoppsecretsyncs.yaml

# Create namespace and credentials
kubectl create namespace zopp-system
kubectl apply -f credentials.yaml

# Deploy operator
kubectl apply -f deploy/operator.yaml
```

## Configuration

### Operator Arguments

| Argument | Env Var | Description | Default |
|----------|---------|-------------|---------|
| `--server` | `ZOPP_SERVER` | Zopp server address | `http://127.0.0.1:50051` |
| `--namespace` | `ZOPP_NAMESPACE` | Watch only this namespace | All namespaces |
| `--health-addr` | `ZOPP_HEALTH_ADDR` | Health check endpoint | `0.0.0.0:8080` |
| `--tls-ca-cert` | `ZOPP_TLS_CA_CERT` | Custom CA cert for TLS | System CAs |

### Health Endpoints

- `/healthz` - Liveness probe (always returns OK)
- `/readyz` - Readiness probe (checks gRPC connection)

## Comparison

| Feature | Annotation Mode | CRD Mode |
|---------|----------------|----------|
| Setup complexity | Low | Medium |
| GitOps friendly | Limited | Yes |
| Status reporting | None | Full (conditions) |
| Cross-namespace | No | Yes |
| Custom labels/annotations | No | Yes |
| Configurable interval | Fixed (60s) | Per-resource |

## Future Enhancements

- [ ] Selective key sync (`spec.keys` to sync only specific keys)
- [ ] Name transformers (UPPER_SNAKE → camelCase)
- [ ] Output formats (JSON, env file)
- [ ] Prometheus metrics
- [ ] Multiple source environments into one Secret
