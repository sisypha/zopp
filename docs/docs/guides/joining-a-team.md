---
sidebar_position: 2
title: Joining a Team
description: Get started after receiving a workspace invite from your team.
---

# Joining a Team

You've received a zopp invite from your team. This guide gets you up and running in under 5 minutes.

## What You Need

- An invite token from your team admin (looks like `inv_...` or a short alphanumeric code)
- Your work email address
- The zopp server URL (ask your admin if not provided)

## Step 1: Install the CLI

```bash
curl -fsSL https://raw.githubusercontent.com/faiscadev/zopp/main/install.sh | sh
```

Make sure `~/.local/bin` is in your PATH:

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

## Step 2: Join the Workspace

Use your invite token to register:

```bash
zopp --server https://zopp.yourcompany.com:50051 join <invite-token> you@company.com
```

This creates your device identity (principal) with secure keypairs stored in `~/.zopp/config.json`.

:::tip
If your team uses a standard server URL, you can set it once:
```bash
export ZOPP_SERVER=https://zopp.yourcompany.com:50051
```
Add this to your shell profile to make it permanent.
:::

## Step 3: Verify Access

List the workspaces you have access to:

```bash
zopp workspace list
```

You should see the workspace you were invited to.

## Step 4: Set Up Your Project

Navigate to your project directory and create a `zopp.toml` config file:

```bash
cd ~/code/my-project
```

Create `zopp.toml`:

```toml
[defaults]
workspace = "acme-corp"
project = "backend"
environment = "development"
```

Ask your team what workspace, project, and environment names to use.

## Step 5: Access Secrets

Now you can work with secrets:

```bash
# List available secrets
zopp secret list

# Get a specific secret
zopp secret get DATABASE_URL

# Run a command with secrets injected
zopp run -- npm start
```

## Common Workflows

### Export to .env file

```bash
zopp secret export -o .env
```

### Switch environments

```bash
# Temporarily use a different environment
zopp secret list -e staging

# Or update zopp.toml for a different default
```

### View your permissions

```bash
zopp permission effective -w acme-corp
```

## Troubleshooting

### "Permission denied"

Your admin may need to grant you access to specific projects or environments:

```bash
# Check what you can access
zopp permission effective -w acme-corp
```

Ask your admin to run:
```bash
zopp permission user-set -w acme-corp --email you@company.com --role read
```

### "Connection refused"

Check that you're using the correct server URL:
```bash
zopp --server https://zopp.yourcompany.com:50051 workspace list
```

### "Invalid invite"

The invite may have expired. Ask your admin for a new one:
```bash
# Admin runs:
zopp invite create -w acme-corp --expires-hours 48
```

## Multiple Devices

You can use zopp from multiple devices. There are two ways to set up a new device:

### Option 1: Export/Import (Recommended)

Export your principal from your current device and import it on your new device. The export is stored securely on the server and protected by a passphrase.

```bash
# On your existing device - create an export
zopp principal export laptop

# Output shows an export code and passphrase:
#   Export code:
#       exp_a7k9m2x4
#
#   Passphrase (write this down):
#       correct horse battery staple purple llama
#
#   This export expires in 24 hours.
#   After 3 failed passphrase attempts, the export is permanently deleted.
```

Write down both the export code and the 6-word passphrase, then on your new device:

```bash
# On your new device - import using the export code and passphrase
zopp --server https://zopp.yourcompany.com:50051 principal import
# Enter export code: exp_a7k9m2x4
# Enter passphrase: correct horse battery staple purple llama

# You're now authenticated!
zopp workspace list
```

:::tip Create exports before traveling
Create an export before you leave, so you can set up your new device without needing access to your old one. Exports last 24 hours.
:::

:::info Security
- The passphrase provides ~77 bits of entropy (6 words from a 7776-word list)
- The server only stores encrypted data—it cannot decrypt your principal
- Each export can only be used once (consumed on import)
- Exports self-destruct after 3 failed passphrase attempts to prevent brute-force attacks
:::

### Option 2: Create a New Principal

If you have access to an existing device, you can create a new principal and immediately export it:

```bash
# On your existing device - create and export in one command
zopp principal create new-laptop --export

# Or create first, then export
zopp principal create new-laptop
zopp principal export new-laptop
```

The new principal automatically gets access to all workspaces your user has access to. Use the generated passphrase to import on your new device.

### Managing Principals

```bash
# Switch between principals on the same device
zopp principal use desktop

# See which principal is active
zopp principal current

# List all principals
zopp principal list
```

When you leave the team or lose a device, your admin can revoke access to that specific principal without affecting your other devices.

## Next Steps

- [Core Concepts](/guides/core-concepts) - Understand workspaces, projects, and environments
- [Import/Export](/guides/import-export) - Work with .env files
- [CLI Reference](/reference/cli) - Full command reference
