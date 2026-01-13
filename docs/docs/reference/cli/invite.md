---
sidebar_position: 7
title: invite
description: Create and manage workspace invitations.
---

# invite

Create and manage workspace invitations. Invites allow new users to join your workspace.

```bash
zopp invite <COMMAND>
```

## Commands

| Command | Description |
|---------|-------------|
| `create` | Create a new workspace invite |
| `list` | List all invites for a workspace |
| `revoke` | Revoke an existing invite |

---

## invite create

Create a new workspace invite. The invite contains an encrypted copy of the workspace KEK that the invitee can decrypt using the invite token.

```bash
zopp invite create [OPTIONS]
```

### Options

| Option | Required | Description |
|--------|----------|-------------|
| `-w, --workspace <WORKSPACE>` | Yes | Workspace to create invite for |
| `--expires-hours <HOURS>` | No | Hours until invite expires (default: 168 = 7 days) |
| `--plain` | No | Output only the invite code (useful for scripts) |
| `-h, --help` | No | Print help |

### Examples

```bash
# Create invite with default expiration (7 days)
$ zopp invite create -w mycompany
Invite created for workspace "mycompany"
Token: inv_a1b2c3d4e5f6...
Expires: 2024-01-15 14:30:00 UTC

Share this token with the user. They can join using:
  zopp join inv_a1b2c3d4e5f6... user@example.com

# Create invite that expires in 24 hours
zopp invite create -w mycompany --expires-hours 24

# Get just the token for scripting
TOKEN=$(zopp invite create -w mycompany --plain)
```

---

## invite list

List all pending invites for workspaces you have access to.

```bash
zopp invite list
```

### Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Print help |

### Example

```bash
$ zopp invite list
WORKSPACE   EXPIRES              STATUS
mycompany   2024-01-15 14:30:00  pending
mycompany   2024-01-10 09:00:00  expired
acme-corp   2024-01-20 00:00:00  pending
```

---

## invite revoke

Revoke a pending invite so it can no longer be used.

```bash
zopp invite revoke <INVITE_ID>
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `INVITE_ID` | Yes | ID of the invite to revoke |

### Example

```bash
$ zopp invite revoke inv_a1b2c3d4e5f6
Invite revoked
```
