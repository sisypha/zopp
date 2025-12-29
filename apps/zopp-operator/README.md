# Zopp Kubernetes Operator

Kubernetes operator that automatically syncs secrets from zopp to Kubernetes Secrets using an annotation-based approach.

## How It Works

The operator watches all Kubernetes Secrets and syncs those annotated with `zopp.dev/sync: "true"`.

### Dual-Sync Strategy

The operator implements two concurrent synchronization mechanisms:

1. **Event Streaming (Primary)** - Real-time updates via gRPC streaming
   - Instant propagation when secrets change (< 1 second latency)
   - Persistent connection with automatic reconnection (5s backoff)
   - Server-side push for efficient resource usage

2. **Periodic Polling (Safeguard)** - Reconciles every 60 seconds
   - Catches any missed events during stream disconnections
   - Detects version drift and triggers resync if needed
   - Ensures eventual consistency even if stream is unavailable

This combines **real-time performance** with **reliability guarantees**.

## Usage

### 1. Create a Kubernetes Secret with Annotations

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: app-secrets
  namespace: default
  annotations:
    zopp.dev/sync: "true"
    zopp.dev/workspace: "acme"
    zopp.dev/project: "backend"
    zopp.dev/environment: "production"
type: Opaque
data: {}  # Will be populated by operator
```

### 2. Run the Operator

```bash
# Using default credentials (~/.zopp/credentials.json)
cargo run --bin zopp-operator

# Using custom credentials
cargo run --bin zopp-operator -- --credentials /path/to/credentials.json

# Watch specific namespace only
cargo run --bin zopp-operator -- --namespace default

# Custom server address
cargo run --bin zopp-operator -- --server http://zopp-server:50051
```

### 3. Verify Synchronization

```bash
# Check Secret data is populated
kubectl get secret app-secrets -o yaml

# Watch operator logs
kubectl logs -f deployment/zopp-operator -n zopp-operator-system
```

## Configuration

### Command-Line Options

```
--server <URL>          Zopp server address (default: http://127.0.0.1:50051)
--credentials <PATH>    Path to credentials file (default: ~/.zopp/credentials.json)
--namespace <NAME>      Namespace to watch (default: all namespaces)
```

### Required Annotations

| Annotation | Description | Example |
|------------|-------------|---------|
| `zopp.dev/sync` | Enable sync (must be `"true"`) | `"true"` |
| `zopp.dev/workspace` | Zopp workspace name | `"acme"` |
| `zopp.dev/project` | Zopp project name | `"backend"` |
| `zopp.dev/environment` | Zopp environment name | `"production"` |

## Setup

The operator authenticates as a service principal. Follow these steps to set it up:

### 1. Create a Service Principal

As a workspace administrator, create a service principal for the operator:

```bash
# Alice creates a service principal for the operator
zopp principal create k8s-operator --service
```

This creates a service principal with no user association (`user_id = NULL`).

### 2. Deploy the Operator

The operator uses the standard zopp configuration file (`~/.zopp/config.json`). You can either:

**Option A: Use the same config as your user**
```bash
# The operator will use the service principal from your config
kubectl create secret generic zopp-config \
  --from-file=config.json=$HOME/.zopp/config.json \
  -n zopp-operator-system
```

**Option B: Create a dedicated config file**
```bash
# Switch to the service principal
zopp principal use k8s-operator

# Export just this principal's config
cp ~/.zopp/config.json /tmp/operator-config.json

# Create K8s secret
kubectl create secret generic zopp-config \
  --from-file=config.json=/tmp/operator-config.json \
  -n zopp-operator-system
```

### 3. Grant Workspace Access

The service principal needs access to the workspace:

```bash
# Create an invite for the workspace
zopp invite create --workspace acme --plain > invite.txt

# Use the invite to add the service principal to the workspace
# (This wraps the workspace KEK for the service principal)
zopp join $(cat invite.txt) k8s-operator@acme.com --principal k8s-operator
```

The operator will fetch and unwrap the workspace KEK at runtime using its X25519 keys.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Kubernetes Cluster                                             │
│                                                                 │
│  ┌──────────────────────┐         ┌──────────────────────┐    │
│  │ Secret (annotated)   │         │ Secret (annotated)   │    │
│  │ zopp.dev/sync: true  │         │ zopp.dev/sync: true  │    │
│  └──────────────────────┘         └──────────────────────┘    │
│           ▲                                 ▲                   │
│           │                                 │                   │
│           │        ┌────────────────────────┤                   │
│           │        │                        │                   │
│           └────────┴────────────────────────┘                   │
│                    │                                            │
│           ┌────────▼──────────┐                                 │
│           │  Zopp Operator    │                                 │
│           │  ┌──────────────┐ │                                 │
│           │  │Event Stream  │ │  Real-time updates              │
│           │  │(gRPC)        │◄┼─────────────────────┐           │
│           │  └──────────────┘ │                     │           │
│           │  ┌──────────────┐ │                     │           │
│           │  │60s Reconcile │ │  Periodic poll      │           │
│           │  │Loop          │◄┼─────────────────┐   │           │
│           │  └──────────────┘ │                 │   │           │
│           └───────────────────┘                 │   │           │
└─────────────────────────────────────────────────┼───┼───────────┘
                                                  │   │
                                                  │   │
                                          ┌───────▼───▼────────┐
                                          │  Zopp Server       │
                                          │  ┌──────────────┐  │
                                          │  │ EventBus     │  │
                                          │  └──────────────┘  │
                                          │  ┌──────────────┐  │
                                          │  │ Secrets DB   │  │
                                          │  └──────────────┘  │
                                          └────────────────────┘
```

## Behavior

### Initial Sync
1. Operator detects annotated Secret
2. Fetches workspace KEK from server (wrapped for this principal)
3. Unwraps KEK using principal's X25519 private key
4. Caches KEK in memory
5. Fetches all secrets from zopp server for that environment
6. Decrypts secrets using KEK→DEK hierarchy
7. Updates Kubernetes Secret data (base64-encoded)

### Real-time Updates (Event Stream)
1. Server publishes event when secret changes (Created/Updated/Deleted)
2. Operator receives event via gRPC stream
3. Fetches updated secret value (if needed)
4. Updates Kubernetes Secret immediately

### Periodic Reconciliation (60s Poll)
1. Every 60 seconds, operator fetches all secrets from server
2. Compares version with last known version
3. If version changed, updates Kubernetes Secret
4. Acts as safety net if stream missed events

### Version Drift Detection
- Server tracks monotonic version counter per environment
- Operator stores last known version
- If client version < server version, triggers full resync
- Ensures operator eventually catches up after downtime

### Error Handling
- Stream disconnection → automatic reconnect with 5s backoff
- API errors during polling → log warning, retry on next interval
- Decryption failures → log error, skip that secret
- Missing annotations → ignore Secret

## Security

### RBAC Permissions

The operator needs:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: zopp-operator
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list", "watch", "patch"]
```

**Note**: The operator has read/write access to Secret values, so credentials must be protected.

### Credential Storage

In production, store credentials in a Kubernetes Secret:

```bash
kubectl create secret generic zopp-credentials \
  --from-file=credentials.json \
  -n zopp-operator-system
```

Mount in deployment:

```yaml
spec:
  containers:
    - name: operator
      volumeMounts:
        - name: credentials
          mountPath: /etc/zopp
          readOnly: true
      env:
        - name: ZOPP_CREDENTIALS
          value: /etc/zopp/credentials.json
  volumes:
    - name: credentials
      secret:
        secretName: zopp-credentials
```

## Deployment

See [deployment manifests](../../deployments/k8s/operator/) for production deployment.

## Development

```bash
# Run locally (requires running zopp server)
cargo run --bin zopp-operator

# Run tests
cargo test --package zopp-operator

# Check code
cargo clippy --package zopp-operator
```

## Design Philosophy

Zopp uses annotations on existing Secrets rather than custom resources:

| Feature | CRD Approach | Zopp (Annotations) |
|---------|--------------|-------------------|
| Sync Method | Polling-based | Event streaming + 60s poll |
| Latency | Seconds to minutes | < 1 second (stream), max 60s (poll) |
| API Load | Multiple requests/min | 1 persistent connection |
| User Experience | Learn new CRD types | Annotate existing Secrets |
| Kubernetes Native | New resource type | Standard Secret resource |
| State Separation | ✅ spec/status | ❌ Mixed |

Both approaches have tradeoffs - we may add CRD support later for users who prefer explicit state separation.

## Future Enhancements

- [ ] CRD support (ZoppSecretSync custom resource)
- [ ] Deployment reload annotations (restart pods on secret change)
- [ ] Selective key sync (`zopp.dev/keys` annotation)
- [ ] Multi-source secrets (merge multiple environments)
- [ ] Metrics and Prometheus integration
- [ ] Helm chart for easy deployment
