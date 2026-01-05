# zopp

Own your secrets. Stay secure. Empower developers.
zopp is the open-source, self-hostable, CLI-first secrets manager that keeps your secrets safe and your workflow fast.

---

## Status

[![Lint](https://github.com/faiscadev/zopp/actions/workflows/lint.yaml/badge.svg)](https://github.com/faiscadev/zopp/actions/workflows/lint.yaml)
[![Build](https://github.com/faiscadev/zopp/actions/workflows/build.yaml/badge.svg)](https://github.com/faiscadev/zopp/actions/workflows/build.yaml)
[![Test](https://github.com/faiscadev/zopp/actions/workflows/test.yaml/badge.svg)](https://github.com/faiscadev/zopp/actions/workflows/test.yaml)
[![Security Audit](https://github.com/faiscadev/zopp/actions/workflows/audit.yaml/badge.svg)](https://github.com/faiscadev/zopp/actions/workflows/audit.yaml)


---

## Why zopp?

- **Open-source**: transparent code, community-driven, contributions encouraged.
- **Self-hostable**: your secrets, your infra — deploy where you trust.
- **Local-first**: works fully offline; no vendor lock-in.
- **Safe**: passphrase → Argon2id; per-environment keys; AEAD for secret values.
- **Developer-focused**: import/export `.env`, inject into processes, zero boilerplate.

---

## Quick Start

### 1. Configure defaults (optional but recommended)

Create a `zopp.toml` in your project directory:

```toml
[defaults]
workspace = "acme"
project = "api"
environment = "development"
```

Supports `zopp.toml`, `zopp.yaml`, `zopp.yml`, or `zopp.json`.

### 2. Manage secrets

```bash
# Set a secret (uses zopp.toml defaults)
zopp secret set DATABASE_URL "postgresql://..."

# Get a secret
zopp secret get DATABASE_URL

# Override environment
zopp secret set API_KEY "prod-key" -e production

# Export to .env file
zopp secret export -o .env

# Inject secrets into a command
zopp run -- npm start
```

See [DEMO.md](./DEMO.md) for the complete workflow.

---

## Installation

### Kubernetes (Helm)

Deploy zopp server and operator to your Kubernetes cluster:

```bash
# Clone the repository
git clone https://github.com/faiscadev/zopp.git
cd zopp

# Install with default settings (server + operator)
helm install zopp ./charts/zopp

# Or customize with your own values
helm install zopp ./charts/zopp \
  --set server.database.type=postgres \
  --set server.database.postgres.url="postgres://user:pass@host/db"

# Operator-only mode (connect to external server)
helm install zopp ./charts/zopp \
  --set server.enabled=false \
  --set operator.server.address="zopp.example.com:50051"
```

See [charts/zopp/README.md](./charts/zopp/README.md) for complete Helm chart documentation.

### CLI Installation

#### Docker (recommended)

```bash
# Pull latest stable release
docker pull ghcr.io/faiscadev/zopp-cli:latest
alias zopp='docker run --rm -v ~/.zopp:/home/zopp/.zopp ghcr.io/faiscadev/zopp-cli:latest'

# Or use edge (latest from main branch)
docker pull ghcr.io/faiscadev/zopp-cli:edge
alias zopp='docker run --rm -v ~/.zopp:/home/zopp/.zopp ghcr.io/faiscadev/zopp-cli:edge'

# Or build locally
docker build -f cli.Dockerfile -t zopp-cli .
```

#### From source

```bash
cargo install --path apps/zopp-cli
```

---

## Build from source

```bash
cargo build --workspace --release
```
