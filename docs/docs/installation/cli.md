---
sidebar_position: 2
title: CLI Installation
description: Install the zopp command-line interface on your machine.
---

# CLI Installation

The zopp CLI is the primary way to interact with zopp. It handles all encryption client-side, so your secrets never leave your machine unencrypted.

## Install Script (Recommended)

The install script automatically detects your platform and installs the latest release:

```bash
curl -fsSL https://raw.githubusercontent.com/faiscadev/zopp/main/install.sh | sh
```

This installs to `~/.local/bin/zopp`. Make sure this directory is in your `PATH`.

## Package Managers

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

<Tabs>
  <TabItem value="cargo" label="Cargo" default>

If you have Rust installed:

```bash
cargo install --git https://github.com/faiscadev/zopp --package zopp-cli
```

  </TabItem>
  <TabItem value="homebrew" label="Homebrew">

Coming soon! For now, use the install script or Cargo.

  </TabItem>
</Tabs>

## Pre-built Binaries

Download pre-built binaries from [GitHub Releases](https://github.com/faiscadev/zopp/releases):

| Platform | Architecture | Download |
|----------|--------------|----------|
| Linux | x86_64 | `zopp-linux-x86_64` |
| Linux | ARM64 | `zopp-linux-arm64` |
| macOS | Intel | `zopp-darwin-x86_64` |
| macOS | Apple Silicon | `zopp-darwin-arm64` |
| Windows | x86_64 | `zopp-windows-x86_64.exe` |

1. Download the binary for your platform
2. Make it executable (Linux/macOS):
   ```bash
   chmod +x zopp-*
   ```
3. Move to a directory in your PATH:
   ```bash
   mv zopp-* /usr/local/bin/zopp
   ```

## Build from Source

1. Install Rust (1.90 or later):
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. Clone and build:
   ```bash
   git clone https://github.com/faiscadev/zopp.git
   cd zopp
   cargo build --release --package zopp-cli
   ```

3. Install:
   ```bash
   cp target/release/zopp ~/.local/bin/
   ```

## Verify Installation

```bash
zopp --version
# zopp 0.1.0
```

## Configuration

The CLI stores configuration in `~/.zopp/config.json`. This file contains:

- Your principal credentials (Ed25519 and X25519 keypairs)
- Server connection settings
- Active principal selection

:::danger
Never share your `~/.zopp/config.json` file. It contains your private keys.
:::

## Shell Completion

Generate shell completions for your shell:

```bash
# Bash
zopp completions bash > ~/.local/share/bash-completion/completions/zopp

# Zsh
zopp completions zsh > ~/.zfunc/_zopp

# Fish
zopp completions fish > ~/.config/fish/completions/zopp.fish
```

## Connecting to a Server

By default, zopp connects to `http://127.0.0.1:50051`. To connect to a different server:

```bash
# Use a flag
zopp --server https://zopp.example.com:50051 workspace list

# Or set an environment variable
export ZOPP_SERVER=https://zopp.example.com:50051
zopp workspace list
```

For self-signed certificates, provide the CA certificate:

```bash
zopp --server https://zopp.example.com:50051 --tls-ca-cert /path/to/ca.crt workspace list

# Or via environment variable
export ZOPP_TLS_CA_CERT=/path/to/ca.crt
```

## Next Steps

- [Quickstart](/quickstart) - Set up your first workspace
- [Docker Installation](/installation/docker) - Run the server in Docker
- [Self-Hosting](/self-hosting) - Deploy your own server
