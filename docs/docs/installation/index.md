---
sidebar_position: 1
title: Installation
description: Choose the best way to install zopp for your setup.
---

# Installation

zopp offers multiple installation methods to fit your workflow. Choose the one that works best for you.

<div className="row">
  <div className="col col--4 margin-bottom--lg">
    <div className="card">
      <div className="card__body">
        <h3>CLI</h3>
        <p>Install the zopp CLI on your local machine for development and daily use.</p>
        <a href="/zopp/installation/cli">Install CLI</a>
      </div>
    </div>
  </div>
  <div className="col col--4 margin-bottom--lg">
    <div className="card">
      <div className="card__body">
        <h3>Docker</h3>
        <p>Run zopp server and CLI using Docker containers.</p>
        <a href="/zopp/installation/docker">Use Docker</a>
      </div>
    </div>
  </div>
  <div className="col col--4 margin-bottom--lg">
    <div className="card">
      <div className="card__body">
        <h3>Kubernetes</h3>
        <p>Deploy zopp to your Kubernetes cluster using Helm.</p>
        <a href="/zopp/installation/kubernetes">Deploy to K8s</a>
      </div>
    </div>
  </div>
</div>

## System Requirements

### CLI
- macOS (Intel or Apple Silicon)
- Linux (x86_64 or ARM64)
- Windows (x86_64)

### Server
- Any platform that can run Rust binaries or Docker
- SQLite (default) or PostgreSQL for storage
- Optional: TLS certificates for secure connections

## Quick Install

The fastest way to get started:

```bash
# Install CLI
curl -fsSL https://raw.githubusercontent.com/faiscadev/zopp/main/install.sh | sh

# Verify installation
zopp --version
```

## Next Steps

After installing the CLI, follow the [quickstart guide](/quickstart) to set up your first workspace.
