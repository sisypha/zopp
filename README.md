# zopp

Own your secrets. Stay secure. Empower developers.
zopp is the open-source, self-hostable, CLI-first secrets manager that keeps your secrets safe and your workflow fast.

---

## Status

[![Lint](https://github.com/faiscadev/zopp/actions/workflows/lint.yaml/badge.svg)](https://github.com/faiscadev/zopp/actions/workflows/lint.yaml)
[![Build](https://github.com/faiscadev/zopp/actions/workflows/build.yaml/badge.svg)](https://github.com/faiscadev/zopp/actions/workflows/build.yaml)
[![Test](https://github.com/faiscadev/zopp/actions/workflows/test.yaml/badge.svg)](https://github.com/faiscadev/zopp/actions/workflows/test.yaml)
[![Security Audit](https://github.com/faiscadev/zopp/actions/workflows/audit.yaml/badge.svg)](https://github.com/faiscadev/zopp/actions/workflows/audit.yaml)
[![Coverage](https://img.shields.io/endpoint?url=https://faiscadev.github.io/zopp/badge.json)](https://faiscadev.github.io/zopp/)


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
# Install from OCI registry (recommended)
helm install zopp oci://ghcr.io/faiscadev/charts/zopp --version 0.1.0

# Or install from source
git clone https://github.com/faiscadev/zopp.git
cd zopp
helm install zopp ./charts/zopp

# Customize with PostgreSQL backend
helm install zopp oci://ghcr.io/faiscadev/charts/zopp \
  --version 0.1.0 \
  --set server.database.type=postgres \
  --set server.database.postgres.url="postgres://user:pass@host/db"

# Operator-only mode (connect to external server)
helm install zopp oci://ghcr.io/faiscadev/charts/zopp \
  --version 0.1.0 \
  --set server.enabled=false \
  --set operator.server.address="zopp.example.com:50051"
```

See [charts/zopp/README.md](./charts/zopp/README.md) for complete Helm chart documentation.

### CLI Installation

#### Using install script (recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/faiscadev/zopp/main/install.sh | sh
```

#### Using Cargo

```bash
cargo install --git https://github.com/faiscadev/zopp --package zopp-cli
```

#### Download pre-built binaries

Download the latest release from [GitHub Releases](https://github.com/faiscadev/zopp/releases).

#### Using Docker

```bash
# Pull latest stable release
docker pull ghcr.io/faiscadev/zopp-cli:latest
alias zopp='docker run --rm -v ~/.zopp:/home/zopp/.zopp ghcr.io/faiscadev/zopp-cli:latest'
```

---

## Build from source

```bash
cargo build --workspace --release
```
