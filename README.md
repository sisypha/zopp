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

### Docker (recommended)

```bash
# Pull and run CLI
docker pull ghcr.io/sisypha/zopp-cli:latest
alias zopp='docker run --rm -v ~/.zopp:/home/zopp/.zopp ghcr.io/sisypha/zopp-cli:latest'

# Or build locally
docker build -f cli.Dockerfile -t zopp-cli .
```

### From source

```bash
cargo install --path apps/zopp-cli
```

---

## Build from source

```bash
cargo build --workspace --release
```
