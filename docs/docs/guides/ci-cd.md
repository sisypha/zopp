---
sidebar_position: 5
title: CI/CD Integration
description: Use service principals to securely access secrets in your CI/CD pipelines.
---

# CI/CD Integration

Service principals let you access zopp secrets from CI/CD pipelines without using personal credentials. This guide covers setting up and using service principals in common CI/CD systems.

## Service Principals

A **service principal** is a non-human identity designed for automation:

- Has its own Ed25519/X25519 keypairs
- Can be scoped to specific workspaces
- Supports fine-grained permissions
- No associated user/email

```bash
# Create a service principal
zopp principal create github-actions --service -w myworkspace
```

## Setting Up CI/CD

1. **Create a service principal**

   ```bash
   zopp principal create ci-deploy --service -w myworkspace
   ```

2. **Grant minimal permissions**

   ```bash
   # Read-only access to production environment
   zopp permission env-set -w myworkspace -p myproject -e production \
     --principal <principal-id> --role read
   ```

3. **Export credentials**

   The service principal's config is in `~/.zopp/config.json`. Store it as a CI secret.

4. **Use in your pipeline**

   Set up the config file and use `zopp run` or `zopp secret export`.

## GitHub Actions

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

<Tabs>
  <TabItem value="run" label="Using zopp run" default>

```yaml
name: Deploy

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install zopp
        run: |
          curl -fsSL https://raw.githubusercontent.com/faiscadev/zopp/main/install.sh | sh
          echo "$HOME/.local/bin" >> $GITHUB_PATH

      - name: Configure zopp
        run: |
          mkdir -p ~/.zopp
          echo '${{ secrets.ZOPP_CONFIG }}' > ~/.zopp/config.json

      - name: Deploy with secrets
        run: |
          zopp run -w myworkspace -p myproject -e production -- ./deploy.sh
```

  </TabItem>
  <TabItem value="export" label="Using export">

```yaml
name: Deploy

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install zopp
        run: |
          curl -fsSL https://raw.githubusercontent.com/faiscadev/zopp/main/install.sh | sh
          echo "$HOME/.local/bin" >> $GITHUB_PATH

      - name: Configure zopp
        run: |
          mkdir -p ~/.zopp
          echo '${{ secrets.ZOPP_CONFIG }}' > ~/.zopp/config.json

      - name: Export secrets
        run: |
          zopp secret export -w myworkspace -p myproject -e production -o .env

      - name: Deploy
        run: |
          . .env
          ./deploy.sh
```

  </TabItem>
</Tabs>

### Storing Credentials in GitHub

1. Go to your repository → Settings → Secrets and variables → Actions
2. Create a new secret named `ZOPP_CONFIG`
3. Paste the contents of `~/.zopp/config.json`

:::danger
The config file contains private keys. Only store it in secure secret storage, never in code.
:::

## GitLab CI

```yaml
# .gitlab-ci.yml
stages:
  - deploy

deploy:
  stage: deploy
  image: ubuntu:latest
  before_script:
    - curl -fsSL https://raw.githubusercontent.com/faiscadev/zopp/main/install.sh | sh
    - export PATH="$HOME/.local/bin:$PATH"
    - mkdir -p ~/.zopp
    - echo "$ZOPP_CONFIG" > ~/.zopp/config.json
  script:
    - zopp run -w myworkspace -p myproject -e production -- ./deploy.sh
  only:
    - main
```

Store `ZOPP_CONFIG` as a CI/CD variable (Settings → CI/CD → Variables, masked and protected).

## CircleCI

```yaml
# .circleci/config.yml
version: 2.1

jobs:
  deploy:
    docker:
      - image: cimg/base:stable
    steps:
      - checkout
      - run:
          name: Install zopp
          command: |
            curl -fsSL https://raw.githubusercontent.com/faiscadev/zopp/main/install.sh | sh
            echo 'export PATH="$HOME/.local/bin:$PATH"' >> $BASH_ENV
      - run:
          name: Configure zopp
          command: |
            mkdir -p ~/.zopp
            echo "$ZOPP_CONFIG" > ~/.zopp/config.json
      - run:
          name: Deploy
          command: zopp run -w myworkspace -p myproject -e production -- ./deploy.sh

workflows:
  deploy:
    jobs:
      - deploy:
          filters:
            branches:
              only: main
```

## Docker/Container Builds

For building containers that need secrets:

```dockerfile
# Dockerfile
FROM node:20 AS builder

# Install zopp
RUN curl -fsSL https://raw.githubusercontent.com/faiscadev/zopp/main/install.sh | sh

# Copy credentials (passed as build secret)
RUN --mount=type=secret,id=zopp_config \
    mkdir -p ~/.zopp && \
    cp /run/secrets/zopp_config ~/.zopp/config.json

# Export secrets and build
RUN zopp secret export -w myworkspace -p myproject -e production -o .env && \
    . .env && \
    npm run build

# Final image (no secrets included)
FROM node:20-slim
COPY --from=builder /app/dist /app/dist
CMD ["node", "/app/dist/index.js"]
```

Build with:

```bash
docker build --secret id=zopp_config,src=$HOME/.zopp/config.json -t myapp .
```

## Environment-Specific Deployments

Use different environments for different deployment stages:

```yaml
# GitHub Actions example
jobs:
  deploy-staging:
    runs-on: ubuntu-latest
    environment: staging
    steps:
      - name: Deploy to staging
        run: zopp run -w myworkspace -p myproject -e staging -- ./deploy.sh

  deploy-production:
    runs-on: ubuntu-latest
    environment: production
    needs: deploy-staging
    steps:
      - name: Deploy to production
        run: zopp run -w myworkspace -p myproject -e production -- ./deploy.sh
```

## Using zopp.toml in CI

Create a `zopp.toml` in your repo to simplify commands:

```toml
[defaults]
workspace = "myworkspace"
project = "myproject"
```

Then in CI:

```bash
# Uses defaults, just specify environment
zopp run -e production -- ./deploy.sh
```

## Multiple Service Principals

For separation of concerns, create different principals per environment or purpose:

```bash
# Staging deployments
zopp principal create ci-staging --service -w myworkspace
zopp permission env-set -w myworkspace -p myproject -e staging \
  --principal <staging-principal-id> --role read

# Production deployments
zopp principal create ci-production --service -w myworkspace
zopp permission env-set -w myworkspace -p myproject -e production \
  --principal <production-principal-id> --role read
```

Store each config as a separate CI secret.

## Best Practices

### 1. Principle of Least Privilege

Only grant the minimum permissions needed:

```bash
# Good: read-only on specific environment
zopp permission env-set -w ws -p proj -e prod --principal <id> --role read

# Avoid: workspace-level admin
zopp permission set -w ws --principal <id> --role admin
```

### 2. Use Descriptive Principal Names

```bash
# Good
zopp principal create github-actions-prod-deploy --service -w myworkspace
zopp principal create gitlab-ci-staging --service -w myworkspace

# Bad
zopp principal create ci --service -w myworkspace
```

### 3. Rotate Credentials Periodically

1. Create a new service principal
2. Update CI secrets
3. Verify deployments work
4. Delete old principal

```bash
# Create new
zopp principal create github-actions-prod-v2 --service -w myworkspace

# Grant same permissions
zopp permission env-set -w ws -p proj -e prod --principal <new-id> --role read

# After updating CI secrets, delete old
zopp principal delete github-actions-prod-v1
```

### 4. Audit Service Principal Usage

```bash
# Check what a principal has accessed
zopp audit list -w myworkspace --limit 100 | grep <principal-id>
```

## Troubleshooting

### Permission Denied

```bash
# Check effective permissions
zopp permission effective -w myworkspace --principal <id>

# Verify principal has access to the workspace
zopp principal service-list -w myworkspace
```

### Connection Errors

Ensure your CI environment can reach the zopp server:

```bash
# Test connectivity
curl -v https://zopp.example.com:50051

# Check TLS CA if using self-signed certs
export ZOPP_TLS_CA_CERT=/path/to/ca.crt
zopp workspace list
```

## Next Steps

- [Kubernetes Operator](/guides/kubernetes-operator) - Sync to Kubernetes
- [CLI Reference](/reference/cli) - Full command reference
