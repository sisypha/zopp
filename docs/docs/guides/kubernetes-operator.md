---
sidebar_position: 4
title: Kubernetes Operator
description: Automatically sync zopp secrets to Kubernetes Secrets.
---

# Kubernetes Operator

The zopp Kubernetes operator watches for `ZoppSecret` custom resources and automatically syncs them to native Kubernetes Secrets. This enables GitOps workflows where secret references are checked into version control while actual values stay secure in zopp.

## How It Works

```
┌─────────────────────────────────────────────────────────┐
│                    Kubernetes Cluster                   │
│                                                         │
│  ┌──────────────┐      watches      ┌───────────────┐  │
│  │ ZoppSecret   │ ◄──────────────── │ zopp-operator │  │
│  │   (CRD)      │                   │               │  │
│  └──────┬───────┘                   └───────┬───────┘  │
│         │                                   │          │
│         │ specifies                         │ fetches  │
│         ▼                                   ▼          │
│  ┌──────────────┐      creates      ┌───────────────┐  │
│  │ K8s Secret   │ ◄──────────────── │ zopp server   │  │
│  └──────────────┘                   │ (gRPC)        │  │
│                                     └───────────────┘  │
└─────────────────────────────────────────────────────────┘
```

1. You create a `ZoppSecret` resource specifying which zopp environment to sync
2. The operator fetches and decrypts secrets from the zopp server
3. The operator creates/updates a native Kubernetes Secret
4. Your pods use the native Secret as normal

## Installation

The operator is included in the zopp Helm chart:

```bash
helm install zopp oci://ghcr.io/faiscadev/charts/zopp --version 0.1.0
```

See [Kubernetes Installation](/zopp/installation/kubernetes) for configuration options.

## Setting Up Operator Credentials

The operator needs credentials to authenticate with the zopp server:

1. **Create a service principal**

   ```bash
   zopp principal create k8s-operator --service -w myworkspace
   ```

2. **Grant appropriate permissions**

   ```bash
   # Read access to the environments it needs to sync
   zopp permission env-set -w myworkspace -p myproject -e production \
     --principal <operator-principal-id> --role read
   ```

3. **Create the Kubernetes secret**

   ```bash
   kubectl create secret generic zopp-operator-credentials \
     --from-file=config.json=$HOME/.zopp/config.json
   ```

4. **Configure the Helm chart**

   ```yaml
   operator:
     credentials:
       existingSecret: zopp-operator-credentials
   ```

## Creating ZoppSecrets

Define which zopp secrets to sync using `ZoppSecret` resources:

```yaml
apiVersion: zopp.dev/v1alpha1
kind: ZoppSecret
metadata:
  name: api-secrets
  namespace: production
spec:
  # Source: zopp coordinates
  workspace: mycompany
  project: api-backend
  environment: production

  # Target: Kubernetes Secret to create
  secretName: api-env

  # Optional: only sync specific keys
  # keys:
  #   - DATABASE_URL
  #   - API_KEY

  # Optional: refresh interval (default: 5m)
  # refreshInterval: 1m
```

Apply it:

```bash
kubectl apply -f zoppsecret.yaml
```

The operator will create a Kubernetes Secret:

```bash
kubectl get secret api-env -o yaml
```

## Using Synced Secrets

Use the synced secrets in your pods like any other Kubernetes Secret:

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

<Tabs>
  <TabItem value="envfrom" label="Environment Variables" default>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: api-server
spec:
  containers:
    - name: api
      image: myapp:latest
      envFrom:
        - secretRef:
            name: api-env
```

  </TabItem>
  <TabItem value="specific" label="Specific Keys">

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: api-server
spec:
  containers:
    - name: api
      image: myapp:latest
      env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: api-env
              key: DATABASE_URL
```

  </TabItem>
  <TabItem value="volume" label="Volume Mount">

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: api-server
spec:
  containers:
    - name: api
      image: myapp:latest
      volumeMounts:
        - name: secrets
          mountPath: /secrets
          readOnly: true
  volumes:
    - name: secrets
      secret:
        secretName: api-env
```

  </TabItem>
</Tabs>

## Selective Syncing

Sync only specific keys:

```yaml
apiVersion: zopp.dev/v1alpha1
kind: ZoppSecret
metadata:
  name: db-credentials
spec:
  workspace: mycompany
  project: api-backend
  environment: production
  secretName: db-creds
  keys:
    - DATABASE_URL
    - DATABASE_PASSWORD
```

## Multiple Environments

Create separate `ZoppSecret` resources for each environment:

```yaml
# production-secrets.yaml
apiVersion: zopp.dev/v1alpha1
kind: ZoppSecret
metadata:
  name: api-secrets
  namespace: production
spec:
  workspace: mycompany
  project: api-backend
  environment: production
  secretName: api-env
---
# staging-secrets.yaml
apiVersion: zopp.dev/v1alpha1
kind: ZoppSecret
metadata:
  name: api-secrets
  namespace: staging
spec:
  workspace: mycompany
  project: api-backend
  environment: staging
  secretName: api-env
```

## Monitoring

### Check ZoppSecret Status

```bash
kubectl get zoppsecrets -A

# Example output:
# NAMESPACE    NAME          WORKSPACE    PROJECT      ENVIRONMENT   SYNCED   AGE
# production   api-secrets   mycompany    api-backend  production    True     5m
# staging      api-secrets   mycompany    api-backend  staging       True     5m
```

### Operator Logs

```bash
kubectl logs -l app.kubernetes.io/component=zopp-operator -f
```

### Events

```bash
kubectl describe zoppsecret api-secrets
```

## Manual Sync with CLI

You can also sync secrets manually using the CLI:

```bash
# Sync to a Kubernetes Secret
zopp sync k8s -w mycompany -p api-backend -e production \
  --namespace production --secret api-env

# Preview changes first
zopp diff k8s -w mycompany -p api-backend -e production \
  --namespace production --secret api-env
```

:::tip
Manual sync is useful for debugging or one-time operations. For production, use the operator for automatic syncing.
:::

## Security Considerations

### Operator Permissions

The operator needs minimal permissions:
- `read` on zopp environments it syncs
- Kubernetes RBAC to create/update Secrets in target namespaces

### Network Security

- The operator connects to the zopp server over gRPC
- Enable TLS for production deployments
- Consider network policies to restrict operator traffic

### Secret Rotation

When you update a secret in zopp:
1. The operator detects the change on the next sync interval
2. The Kubernetes Secret is updated
3. Pods using `envFrom` get new values on restart
4. Pods using volume mounts get updates automatically (with a delay)

## Troubleshooting

### Secret Not Syncing

```bash
# Check ZoppSecret status
kubectl describe zoppsecret <name>

# Check operator logs
kubectl logs -l app.kubernetes.io/component=zopp-operator --tail=100

# Verify operator credentials
kubectl get secret zopp-operator-credentials -o yaml
```

### Permission Denied

Ensure the operator's principal has read access:

```bash
zopp permission effective -w myworkspace --principal <operator-principal-id>
```

### TLS Errors

If using TLS, ensure the CA certificate is properly mounted:

```yaml
operator:
  server:
    address: "https://zopp.example.com:50051"
    tls:
      existingSecret: zopp-server-ca
```

## Next Steps

- [CI/CD Integration](/zopp/guides/ci-cd) - Automate secret deployment
- [Self-Hosting](/zopp/self-hosting) - Deploy your own zopp server
- [CLI Reference](/zopp/reference/cli) - CLI sync reference
