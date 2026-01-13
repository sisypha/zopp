---
sidebar_position: 1
title: join
description: Register with a server or accept a workspace invitation.
---

# join

Register with a zopp server using an invite token. This is typically the first command you run when setting up zopp.

```bash
zopp join [OPTIONS] <TOKEN> <EMAIL>
```

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `TOKEN` | Yes | Invite token (from server admin or workspace invite) |
| `EMAIL` | Yes | Your email address |

## Options

| Option | Required | Description |
|--------|----------|-------------|
| `--principal <NAME>` | No | Principal name (defaults to hostname) |
| `-h, --help` | No | Print help |

## What Happens

When you run `zopp join`:

1. **Generates keypairs** - Creates Ed25519 (signing) and X25519 (encryption) keypairs on your device
2. **Registers with server** - Sends your public keys to the server
3. **Creates principal** - A principal (device identity) is created and linked to your email
4. **Stores credentials** - Saves your keypairs in `~/.zopp/config.json`
5. **If workspace invite** - Receives the workspace KEK wrapped for your public key

## Examples

### First-time Setup (Server Invite)

When a server admin gives you an invite token:

```bash
$ zopp join inv_server_abc123... alice@example.com
Registered successfully!
Principal: alices-macbook
User: alice@example.com

You can now create workspaces or wait for workspace invites.
```

### Joining a Workspace

When a teammate invites you to their workspace:

```bash
$ zopp join inv_workspace_xyz789... alice@example.com
Registered successfully!
Principal: alices-macbook
User: alice@example.com
Workspace: mycompany (member)

You now have access to the "mycompany" workspace.
```

### Custom Principal Name

By default, the principal is named after your hostname. You can specify a custom name:

```bash
zopp join inv_abc123... alice@example.com --principal work-laptop
```

## Credentials Storage

After joining, your credentials are stored in `~/.zopp/config.json`:

```json
{
  "server": "https://zopp.example.com:50051",
  "principals": [
    {
      "name": "alices-macbook",
      "email": "alice@example.com",
      "signing_key": "...",
      "encryption_key": "..."
    }
  ],
  "current_principal": "alices-macbook"
}
```

:::warning
Keep your `~/.zopp/` directory secure. It contains your private keys.
:::

## See Also

- [Quickstart](/quickstart) - Get started with zopp
- [principal create](/reference/cli/principal) - Create additional principals
