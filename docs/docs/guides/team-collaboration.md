---
sidebar_position: 3
title: Team Collaboration
description: Invite team members, manage permissions, and share secrets securely.
---

# Team Collaboration

zopp makes it easy to share secrets securely with your team. This guide covers inviting members, managing permissions, and organizing access with groups.

## Inviting Team Members

There are two types of invites in zopp:

1. **Server invites** - Allow new users to register on the server
2. **Workspace invites** - Grant access to a specific workspace

### Server Invites (Admin Only)

Server invites are created by the server administrator and allow new users to register:

```bash
# Run on the server (or via kubectl exec)
zopp-server invite create --expires-hours 48 --db /path/to/zopp.db
```

Share this token with the new user. They use it to create their account:

```bash
zopp join <server-token> newuser@company.com
```

### Workspace Invites

Once a user is registered, workspace owners can invite them:

```bash
# Create a workspace invite (valid for 7 days by default)
zopp invite create -w acme-corp --expires-hours 168
```

The invite code looks like: `inv_4f8a2b3c1de56f789a0b1c2d3e4f56789...`

:::note
The invite code contains an encrypted copy of the workspace KEK. The server only stores a hash—it never sees the decryption key.
:::

The invitee accepts with:

```bash
zopp join <workspace-invite> newuser@company.com
```

## Managing Permissions

zopp uses Role-Based Access Control (RBAC) with three roles:

| Role | Capabilities |
|------|--------------|
| `read` | View secrets |
| `write` | View and modify secrets |
| `admin` | Full control including managing permissions |

### Permission Levels

Permissions can be set at three levels:

```
Workspace
 └── Project
      └── Environment
```

Higher-level permissions cascade down. A workspace admin automatically has admin access to all projects and environments.

### Setting Permissions

**By principal ID:**

```bash
# Get the principal ID
zopp principal service-list -w acme-corp

# Grant workspace-level access
zopp permission set -w acme-corp --principal <principal-id> --role write

# Grant project-level access
zopp permission project-set -w acme-corp -p api-backend --principal <principal-id> --role read

# Grant environment-level access
zopp permission env-set -w acme-corp -p api-backend -e production --principal <principal-id> --role read
```

**By email (for all user's principals):**

```bash
# Grant workspace access to a user
zopp permission user-set -w acme-corp --email dev@company.com --role write

# Restrict to read-only on production
zopp permission user-env-set -w acme-corp -p api-backend -e production \
  --email dev@company.com --role read
```

### Viewing Permissions

```bash
# List all permissions on a workspace
zopp permission list -w acme-corp
zopp permission user-list -w acme-corp

# Check effective permissions for a principal
zopp permission effective -w acme-corp --principal <principal-id>
```

### Removing Access

```bash
# Remove workspace access
zopp permission remove -w acme-corp --principal <principal-id>

# Remove a user completely
zopp permission user-remove -w acme-corp --email former@company.com
```

## Using Groups

Groups make it easier to manage permissions for teams:

### 1. Create a group

```bash
zopp group create -w acme-corp backend-team -d "Backend engineering team"
```

### 2. Add members

```bash
zopp group add-member -w acme-corp -g backend-team alice@company.com
zopp group add-member -w acme-corp -g backend-team bob@company.com
```

### 3. Set group permissions

```bash
# Group gets write access to backend project
zopp group set-project-permission -w acme-corp -p api-backend -g backend-team --role write

# But only read access to production
zopp group set-env-permission -w acme-corp -p api-backend -e production -g backend-team --role read
```

### Managing Groups

```bash
# List groups
zopp group list -w acme-corp

# List members
zopp group list-members -w acme-corp -g backend-team

# Remove a member
zopp group remove-member -w acme-corp -g backend-team alice@company.com

# Delete a group
zopp group delete -w acme-corp backend-team
```

## Best Practices

### 1. Use the Principle of Least Privilege

Start with minimal permissions and add more as needed:

```bash
# Default: read-only to workspace
zopp permission user-set -w acme-corp --email dev@company.com --role read

# Add write to specific project
zopp permission user-project-set -w acme-corp -p their-project \
  --email dev@company.com --role write
```

### 2. Protect Production

Restrict production access to senior team members:

```bash
# Most developers can only read production
zopp permission user-env-set -w acme-corp -p api-backend -e production \
  --email junior@company.com --role read

# Senior devs get write access
zopp permission user-env-set -w acme-corp -p api-backend -e production \
  --email senior@company.com --role write
```

### 3. Use Groups for Teams

Instead of managing individual permissions:

```bash
# Create team groups
zopp group create -w acme-corp frontend-team
zopp group create -w acme-corp backend-team
zopp group create -w acme-corp devops-team

# Set permissions on groups
zopp group set-project-permission -w acme-corp -p web-frontend -g frontend-team --role write
zopp group set-project-permission -w acme-corp -p api-backend -g backend-team --role write
zopp group set-permission -w acme-corp -g devops-team --role admin
```

### 4. Audit Regularly

Review who has access:

```bash
# List all workspace permissions
zopp permission user-list -w acme-corp

# Check audit logs
zopp audit list -w acme-corp --limit 100
```

### 5. Offboard Properly

When someone leaves:

```bash
# Remove from all groups first
zopp group remove-member -w acme-corp -g backend-team former@company.com

# Then remove direct permissions
zopp permission user-remove -w acme-corp --email former@company.com

# Revoke any outstanding invites
zopp invite list
zopp invite revoke <invite-code>
```

## Revoking Access

When you remove someone's access:

1. They can no longer fetch new secrets
2. They can no longer decrypt secrets (they don't have the KEK)
3. Their principals are removed from the workspace

:::caution
Removing access doesn't rotate keys. If you're concerned about a compromised principal, consider rotating affected secrets.
:::

## Next Steps

- [Core Concepts](/guides/core-concepts) - Understand the permission hierarchy
- [CI/CD Integration](/guides/ci-cd) - Set up service principals for automation
- [CLI Reference](/reference/cli) - Full command reference
