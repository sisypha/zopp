# Zopp K8s Sync E2E Test

End-to-end test for `zopp sync k8s` command that validates secret synchronization to Kubernetes.

## What it tests

This test validates the complete k8s sync workflow:
- kind cluster creation and cleanup
- Secret sync from zopp to Kubernetes
- Kubernetes Secret verification (data, labels, annotations)
- Secret updates and re-sync
- Ownership validation (--force flag)

## Prerequisites

You need these tools installed:
- **kind** - Kubernetes in Docker
  ```bash
  # macOS
  brew install kind

  # Linux
  curl -Lo ./kind https://kind.sigs.k8s.io/dl/latest/kind-linux-amd64
  chmod +x ./kind
  sudo mv ./kind /usr/local/bin/kind
  ```

- **kubectl** - Kubernetes CLI
  ```bash
  # macOS
  brew install kubectl

  # Linux
  curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
  chmod +x kubectl
  sudo mv kubectl /usr/local/bin/
  ```

- **Docker** - Required for kind
  - macOS: Docker Desktop
  - Linux: Docker Engine

## Running the test

```bash
# From repo root - requires binaries to be built first
cargo build --bins
cargo run --bin zopp-e2e-test-k8s
```

## What gets verified

✅ kind cluster creation and deletion
✅ zopp server starts and accepts connections
✅ Alice registers and creates workspace/project/environment
✅ Secrets are written to zopp
✅ `zopp sync k8s` syncs secrets to Kubernetes Secret
✅ Kubernetes Secret contains correct data
✅ Metadata labels (`app.kubernetes.io/managed-by: zopp`)
✅ Metadata annotations (`zopp.dev/workspace`, `zopp.dev/project`, `zopp.dev/environment`)
✅ Secret updates propagate on re-sync
✅ Ownership validation (sync fails without --force on non-zopp Secret)
✅ `--force` flag takes ownership of existing Secrets

## Test flow

1. **Setup**: Create kind cluster, start zopp-server
2. **Alice registration**: Join server, create workspace/project/environment
3. **Write secrets**: Set DATABASE_URL, API_KEY, REDIS_URL
4. **Initial sync**: `zopp sync k8s --namespace default --secret zopp-test-secrets`
5. **Verify**: Check k8s Secret exists with correct data and metadata
6. **Update secret**: Change DATABASE_URL value
7. **Re-sync**: Sync again and verify update propagated
8. **Force flag test**:
   - Create non-zopp Secret
   - Sync without --force (should fail)
   - Sync with --force (should succeed)
9. **Cleanup**: Delete cluster, stop server

## Test isolation

- Uses `/tmp/zopp-e2e-test-k8s` directory
- Dedicated kind cluster `zopp-test`
- Temporary database
- Cleans up on completion (even on failure)

## Troubleshooting

**kind cluster creation fails:**
- Check Docker is running: `docker ps`
- Delete existing cluster: `kind delete cluster --name zopp-test`

**kubectl connection errors:**
- Verify kubeconfig: `kubectl config current-context`
- Should show: `kind-zopp-test`

**Test hangs:**
- Check server logs in `/tmp/zopp-e2e-test-k8s/`
- Kill stray processes: `pkill -f zopp-server`
- Delete cluster: `kind delete cluster --name zopp-test`
