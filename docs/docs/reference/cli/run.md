---
sidebar_position: 13
title: run
description: Run commands with secrets injected as environment variables.
---

# run

Run a command with all secrets from an environment injected as environment variables. This is the recommended way to use secrets in development and scripts.

```bash
zopp run [OPTIONS] [--] <COMMAND>...
```

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `COMMAND...` | Yes | Command and arguments to run |

## Options

| Option | Required | Description |
|--------|----------|-------------|
| `-w, --workspace <WORKSPACE>` | No | Workspace name (defaults from zopp.toml) |
| `-p, --project <PROJECT>` | No | Project name (defaults from zopp.toml) |
| `-e, --environment <ENVIRONMENT>` | No | Environment name (defaults from zopp.toml) |
| `-h, --help` | No | Print help |

## How It Works

1. Fetches all secrets from the specified environment
2. Decrypts them client-side
3. Injects them as environment variables
4. Executes your command with those variables
5. Secrets are never written to disk

## Examples

### Basic Usage

```bash
# Run npm start with secrets injected
zopp run -- npm start

# Run a Python script
zopp run -- python app.py

# Run with explicit environment
zopp run -e production -- ./deploy.sh
```

### With zopp.toml

Create a `zopp.toml` in your project:

```toml
[defaults]
workspace = "mycompany"
project = "backend"
environment = "development"
```

Then simply run:

```bash
zopp run -- npm start
```

### Verify Secrets Are Injected

```bash
# Print a specific secret
zopp run -- printenv DATABASE_URL

# List all environment variables
zopp run -- env | grep -E "^(DATABASE|API|SECRET)"
```

### Docker Integration

```bash
# Run a container with secrets
zopp run -- docker run -e DATABASE_URL -e API_KEY myapp:latest
```

### Shell Commands

Use `--` to separate zopp options from the command:

```bash
# Run a shell command
zopp run -- sh -c 'echo "DB is $DATABASE_URL"'

# Pipe commands
zopp run -- sh -c 'psql $DATABASE_URL -c "SELECT 1"'
```

### Different Environments

```bash
# Development
zopp run -e development -- npm run dev

# Staging
zopp run -e staging -- npm run test:e2e

# Production (be careful!)
zopp run -e production -- npm run migrate
```

## Security Notes

- Secrets are decrypted in memory and passed to the subprocess
- Secrets are **not** written to any file
- The subprocess inherits the secrets as environment variables
- Child processes of the command will also have access to the secrets

:::tip
For production deployments, consider using the [Kubernetes Operator](/guides/kubernetes-operator) or [CI/CD integration](/guides/ci-cd) instead of `zopp run`.
:::

## See Also

- [secret export](/reference/cli/secret#secret-export) - Export secrets to a .env file
- [CI/CD Integration](/guides/ci-cd) - Use secrets in CI pipelines
