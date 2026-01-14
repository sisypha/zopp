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

You can use zopp from multiple devices. There are three ways to set up a new device:

### Option 1: Export/Import (Recommended)

Transfer your existing principal to a new device:

```bash
# On your existing device - export your principal
zopp principal export laptop -o principal.enc
# Enter a passphrase to encrypt the export
```

Transfer the `principal.enc` file to your new device (via USB, secure messaging, etc.), then:

```bash
# On your new device - import the principal
zopp principal import -i principal.enc
# Enter the passphrase to decrypt
```

### Option 2: Self-Invite

Create a self-invite that only you can use. This is useful when you don't have physical access to your existing device (e.g., adding a new work laptop without your personal laptop nearby):

```bash
# On your existing device - create a self-invite
zopp invite create-self -w acme-corp --plain
# Returns: inv_xxx...
```

On your new device, use the invite with your email:

```bash
# On your new device
zopp join inv_xxx... you@company.com --principal my-new-laptop
```

:::info Self-invites vs regular invites
- **Self-invite**: Any workspace member can create one (read, write, or admin role). Can only be used by the same user.
- **Regular invite**: Requires admin role. Can be used by anyone.
:::

### Option 3: Create a New Principal Locally

If you have access to an existing device, you can create a new principal that automatically inherits workspace access:

```bash
# On your existing device
zopp principal create desktop

# List all your principals
zopp principal list
```

The new principal's keys are saved locally. To use it on a different device, use export/import or self-invite as shown above.

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
