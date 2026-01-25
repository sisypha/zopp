---
sidebar_position: 3
title: Environment Variables
description: Configure zopp using environment variables.
---

# Environment Variables

zopp can be configured using environment variables as an alternative to command-line flags or configuration files.

## Connection

| Variable | Description | Default |
|----------|-------------|---------|
| `ZOPP_SERVER` | Server address | `http://127.0.0.1:50051` |
| `ZOPP_TLS_CA_CERT` | Path to CA certificate for TLS verification | None |

## Defaults

| Variable | Description | Default |
|----------|-------------|---------|
| `ZOPP_WORKSPACE` | Default workspace name | None |
| `ZOPP_PROJECT` | Default project name | None |
| `ZOPP_ENVIRONMENT` | Default environment name | None |

## Server Configuration (zopp-server)

These variables configure the zopp server process.

### Email Verification

| Variable | Description | Default |
|----------|-------------|---------|
| `ZOPP_EMAIL_VERIFICATION_REQUIRED` | Require email verification for new users | `true` (when provider configured) |
| `ZOPP_EMAIL_PROVIDER` | Email provider: `resend` or `smtp` | None |
| `ZOPP_EMAIL_FROM` | Sender email address | Required when provider set |
| `ZOPP_EMAIL_FROM_NAME` | Sender display name | None |

### Resend Provider

| Variable | Description | Default |
|----------|-------------|---------|
| `RESEND_API_KEY` | Resend API key | Required for Resend |

### SMTP Provider

| Variable | Description | Default |
|----------|-------------|---------|
| `SMTP_HOST` | SMTP server hostname | Required for SMTP |
| `SMTP_PORT` | SMTP server port | `587` |
| `SMTP_USERNAME` | SMTP authentication username | None |
| `SMTP_PASSWORD` | SMTP authentication password | None |
| `SMTP_USE_TLS` | Enable TLS/STARTTLS | `true` |

## Precedence

Configuration is resolved in this order (highest to lowest priority):

1. Command-line flags (`--server`, `-w`, etc.)
2. Environment variables
3. Configuration file (`zopp.toml`)
4. Built-in defaults

## Examples

### Connect to a remote server

```bash
export ZOPP_SERVER=https://zopp.example.com:50051
export ZOPP_TLS_CA_CERT=/path/to/ca.crt
zopp workspace list
```

### Set defaults for a session

```bash
export ZOPP_WORKSPACE=mycompany
export ZOPP_PROJECT=api-backend
export ZOPP_ENVIRONMENT=staging

# Now these use the environment defaults
zopp secret list
zopp secret get DATABASE_URL
```

### CI/CD environments

```yaml
# GitHub Actions
env:
  ZOPP_SERVER: https://zopp.example.com:50051
  ZOPP_WORKSPACE: mycompany
  ZOPP_PROJECT: api-backend
  ZOPP_ENVIRONMENT: production
```

## See Also

- [Configuration Reference](/reference/configuration) - File-based configuration
- [CLI Reference](/reference/cli) - Command-line options
