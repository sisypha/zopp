# Zopp Helm Chart

This Helm chart deploys zopp, a zero-knowledge secrets manager, to Kubernetes.

## Versioning

This chart uses **coupled versioning** - the chart version matches the zopp application version:
- Chart v0.2.0 = zopp v0.2.0
- When you upgrade to chart v0.3.0, you get zopp v0.3.0

This means every zopp release includes a corresponding chart release, making upgrades simple and predictable.

## Components

- **Server** (optional): gRPC server that stores encrypted secrets
- **Operator**: Kubernetes operator that syncs zopp secrets to K8s Secrets

## Installation

### From OCI Registry (Recommended)

```bash
# Install latest version
helm install zopp oci://ghcr.io/faiscadev/charts/zopp --version 0.1.0

# Or from GitHub release
helm install zopp https://github.com/faiscadev/zopp/releases/download/v0.1.0/zopp-0.1.0.tgz
```

### From Source

```bash
git clone https://github.com/faiscadev/zopp.git
cd zopp
helm install zopp ./charts/zopp
```

### Quick Start (Server + Operator)

Deploy both server and operator in the same cluster:

```bash
helm install zopp oci://ghcr.io/faiscadev/charts/zopp --version 0.1.0
```

This will:
- Deploy the zopp server with SQLite storage
- Deploy the operator watching all namespaces
- Create necessary RBAC resources

### Operator-Only Mode

If you have a zopp server running elsewhere (e.g., shared server for multiple clusters):

1. First, create operator credentials:

```bash
# On your machine with zopp CLI installed
zopp join <invite-token> operator@cluster-prod
```

This creates `~/.zopp/config.json`. You need to create a Kubernetes secret from it:

```bash
kubectl create secret generic zopp-operator-credentials \
  --from-file=config.json=$HOME/.zopp/config.json
```

2. Install the chart with server disabled:

```bash
helm install zopp oci://ghcr.io/faiscadev/charts/zopp \
  --version 0.1.0 \
  --set server.enabled=false \
  --set operator.server.address="zopp.example.com:50051" \
  --set operator.credentials.existingSecret="zopp-operator-credentials"
```

### Server-Only Mode

Deploy just the server (if you want to run operators in other clusters):

```bash
helm install zopp oci://ghcr.io/faiscadev/charts/zopp \
  --version 0.1.0 \
  --set operator.enabled=false \
  --set server.database.type=postgres \
  --set server.database.postgres.url="postgres://user:pass@rds.amazonaws.com/zopp"
```

## Configuration

### Server Configuration

#### SQLite (Default)

```yaml
server:
  enabled: true
  database:
    type: sqlite
    sqlite:
      path: /data/zopp.db
      persistence:
        enabled: true
        size: 1Gi
```

#### PostgreSQL

```yaml
server:
  enabled: true
  database:
    type: postgres
    postgres:
      # Option 1: Direct URL
      url: "postgres://user:password@host:5432/database"

      # Option 2: Existing secret
      existingSecret: "zopp-db-credentials"
      existingSecretKey: "DATABASE_URL"
```

To create the secret:

```bash
kubectl create secret generic zopp-db-credentials \
  --from-literal=DATABASE_URL="postgres://user:password@host:5432/database"
```

#### TLS/mTLS

Enable TLS for the server:

```yaml
server:
  tls:
    enabled: true
    # Option 1: Use existing secret
    existingSecret: "zopp-server-tls"

    # Option 2: Provide inline (not recommended for production)
    cert: |
      -----BEGIN CERTIFICATE-----
      ...
      -----END CERTIFICATE-----
    key: |
      -----BEGIN PRIVATE KEY-----
      ...
      -----END PRIVATE KEY-----
    # Optional: Enable mTLS
    clientCA: |
      -----BEGIN CERTIFICATE-----
      ...
      -----END CERTIFICATE-----
```

To create TLS secret:

```bash
kubectl create secret generic zopp-server-tls \
  --from-file=tls.crt=server.crt \
  --from-file=tls.key=server.key \
  --from-file=ca.crt=ca.crt  # Optional for mTLS
```

### Operator Configuration

#### Basic Configuration

```yaml
operator:
  enabled: true

  # Watch specific namespace (leave empty for all namespaces)
  watchNamespace: "production"

  # Credentials (required)
  credentials:
    existingSecret: "zopp-operator-credentials"
```

#### Cluster-Wide Operator

To watch all namespaces across the cluster:

```yaml
operator:
  watchNamespace: ""  # Empty = all namespaces

rbac:
  clusterWide: true  # Creates ClusterRole instead of Role
```

#### Connecting to External Server

```yaml
server:
  enabled: false  # Don't deploy server

operator:
  server:
    address: "zopp.example.com:50051"
    tls:
      enabled: true
      existingSecret: "zopp-server-ca"  # Contains ca.crt
```

## Values Reference

### Server Values

| Parameter | Description | Default |
|-----------|-------------|---------|
| `server.enabled` | Deploy server | `true` |
| `server.replicaCount` | Number of server replicas | `1` |
| `server.image.repository` | Server image | `ghcr.io/faiscadev/zopp-server` |
| `server.image.tag` | Server image tag | Chart appVersion |
| `server.database.type` | Database type (`sqlite` or `postgres`) | `sqlite` |
| `server.database.sqlite.path` | SQLite database path | `/data/zopp.db` |
| `server.database.sqlite.persistence.enabled` | Enable persistent volume | `true` |
| `server.database.sqlite.persistence.size` | PVC size | `1Gi` |
| `server.database.postgres.url` | PostgreSQL connection string | `""` |
| `server.database.postgres.existingSecret` | Existing secret for DB URL | `""` |
| `server.tls.enabled` | Enable TLS | `false` |
| `server.service.type` | Service type | `ClusterIP` |
| `server.service.grpcPort` | gRPC port | `50051` |
| `server.service.httpPort` | HTTP health check port | `8080` |

### Operator Values

| Parameter | Description | Default |
|-----------|-------------|---------|
| `operator.enabled` | Deploy operator | `true` |
| `operator.replicaCount` | Number of operator replicas | `1` |
| `operator.image.repository` | Operator image | `ghcr.io/faiscadev/zopp-operator` |
| `operator.image.tag` | Operator image tag | Chart appVersion |
| `operator.server.address` | Server gRPC address | Auto-generated if server enabled |
| `operator.watchNamespace` | Namespace to watch (empty = all) | `""` |
| `operator.credentials.existingSecret` | Secret containing zopp config | Required |
| `operator.healthCheck.port` | Health check port | `8080` |

### RBAC Values

| Parameter | Description | Default |
|-----------|-------------|---------|
| `rbac.create` | Create RBAC resources | `true` |
| `rbac.clusterWide` | Use ClusterRole for all namespaces | `false` |

## Examples

### Production Setup with External RDS

```yaml
# values-production.yaml
server:
  enabled: true
  replicaCount: 2

  database:
    type: postgres
    postgres:
      existingSecret: zopp-rds-credentials
      existingSecretKey: DATABASE_URL

  tls:
    enabled: true
    existingSecret: zopp-server-tls

  resources:
    limits:
      cpu: 1000m
      memory: 1Gi
    requests:
      cpu: 200m
      memory: 256Mi

operator:
  enabled: true
  watchNamespace: ""  # Watch all namespaces

  credentials:
    existingSecret: zopp-operator-credentials

  resources:
    limits:
      cpu: 500m
      memory: 512Mi
    requests:
      cpu: 100m
      memory: 128Mi

rbac:
  clusterWide: true

# Install
helm install zopp ./charts/zopp -f values-production.yaml
```

### Multi-Cluster Setup

**Central Server Cluster:**

```yaml
# values-central.yaml
server:
  enabled: true
  database:
    type: postgres
    postgres:
      url: "postgres://..."

operator:
  enabled: false  # No operator in central cluster

# Install
helm install zopp ./charts/zopp -f values-central.yaml
```

**Edge Clusters (Operators Only):**

```yaml
# values-edge.yaml
server:
  enabled: false

operator:
  enabled: true
  server:
    address: "zopp.central.example.com:50051"
    tls:
      enabled: true
      existingSecret: zopp-central-ca

  credentials:
    existingSecret: zopp-operator-credentials

  watchNamespace: ""

rbac:
  clusterWide: true

# Install in each edge cluster
helm install zopp ./charts/zopp -f values-edge.yaml
```

## Upgrading

```bash
helm upgrade zopp oci://ghcr.io/faiscadev/charts/zopp --version 0.1.1
```

## Uninstalling

```bash
helm uninstall zopp
```

Note: PersistentVolumeClaims are not automatically deleted. Delete manually if needed:

```bash
kubectl delete pvc -l app.kubernetes.io/instance=zopp
```

## Troubleshooting

### Operator can't connect to server

Check the operator logs:

```bash
kubectl logs -l app.kubernetes.io/component=operator
```

Verify the server address:

```bash
kubectl get svc
```

### Server won't start with PostgreSQL

Check server logs:

```bash
kubectl logs -l app.kubernetes.io/component=server
```

Verify DATABASE_URL is correct:

```bash
kubectl get secret zopp-db-credentials -o jsonpath='{.data.DATABASE_URL}' | base64 -d
```

### RBAC permission errors

If operator can't watch secrets:

```bash
# Check RBAC
kubectl get role,rolebinding -l app.kubernetes.io/instance=zopp

# For cluster-wide
kubectl get clusterrole,clusterrolebinding -l app.kubernetes.io/instance=zopp
```

## License

See the main zopp repository for license information.
