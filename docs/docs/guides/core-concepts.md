---
sidebar_position: 2
title: Core Concepts
description: Understand the fundamental concepts of zopp - workspaces, projects, environments, and the key hierarchy.
---

# Core Concepts

This guide explains the core concepts that make zopp work. Understanding these will help you organize your secrets effectively and take full advantage of zopp's security model.

## The Hierarchy

zopp organizes secrets in a three-level hierarchy:

```
Workspace
 └── Project
      └── Environment
           └── Secrets
```

### Workspaces

A **workspace** is the top-level container, typically representing your organization or team.

```bash
zopp workspace create acme-corp
```

Workspaces:
- Have their own Key Encryption Key (KEK)
- Can contain multiple projects
- Are the unit of access control for inviting team members
- Are isolated from other workspaces

:::tip
Most teams need only one workspace. Create additional workspaces if you have completely separate teams or organizations that should never share secrets.
:::

### Projects

A **project** groups related environments, typically representing an application or service.

```bash
zopp project create api-backend -w acme-corp
zopp project create web-frontend -w acme-corp
zopp project create mobile-app -w acme-corp
```

Projects:
- Belong to exactly one workspace
- Can have different permission sets than the workspace
- Help organize secrets by application

### Environments

An **environment** contains the actual secrets, representing a deployment context.

```bash
zopp environment create development -w acme-corp -p api-backend
zopp environment create staging -w acme-corp -p api-backend
zopp environment create production -w acme-corp -p api-backend
```

Environments:
- Have their own Data Encryption Key (DEK)
- Contain the actual secret key-value pairs
- Enable separate permissions per environment (e.g., only admins can read production)

## Key Hierarchy

zopp uses a hierarchical key structure for zero-knowledge encryption:

```
User
 └── Principal (your device)
      ├── Ed25519 keypair (authentication)
      └── X25519 keypair (encryption)
           └── Workspace
                └── KEK (wrapped per-principal)
                     └── Environment
                          └── DEK (wrapped with KEK)
                               └── Secrets (encrypted with DEK)
```

### Principals

A **principal** is a device or credential that can access zopp. When you run `zopp join`, you create a principal.

- Each principal has its own Ed25519 (signing) and X25519 (encryption) keypairs
- Principals are stored in `~/.zopp/config.json`
- You can have multiple principals on the same machine

```bash
# List your principals
zopp principal list

# Create a new principal for another device
zopp principal create work-laptop

# Switch between principals
zopp principal use work-laptop
```

### Workspace KEK

Each workspace has a Key Encryption Key (KEK):
- Generated when the workspace is created
- 32 bytes, randomly generated
- **Wrapped** (encrypted) separately for each principal using X25519 ECDH
- The server stores only the wrapped KEK, never the plaintext

When you invite someone to a workspace:
1. Your client unwraps your copy of the KEK
2. Your client wraps the KEK for the invitee's public key
3. The server stores the newly wrapped KEK

### Environment DEK

Each environment has a Data Encryption Key (DEK):
- Generated when the environment is created
- 32 bytes, randomly generated
- Wrapped with the workspace KEK
- Used to encrypt/decrypt all secrets in that environment

### Secret Encryption

Secrets are encrypted using XChaCha20-Poly1305 AEAD:
- Each secret has its own random nonce
- Additional Authenticated Data (AAD) includes workspace, project, environment, and key name
- Only the ciphertext and nonce are stored on the server

## Project Configuration

Instead of typing `-w`, `-p`, `-e` flags every time, create a `zopp.toml` in your project directory:

```toml
[defaults]
workspace = "acme-corp"
project = "api-backend"
environment = "development"
```

zopp searches for configuration files up the directory tree:
- `zopp.toml`
- `zopp.yaml` / `zopp.yml`
- `zopp.json`

With this configuration, commands become simple:

```bash
# These are equivalent:
zopp secret set API_KEY "secret123" -w acme-corp -p api-backend -e development
zopp secret set API_KEY "secret123"

# Override for a different environment:
zopp secret set API_KEY "prod-secret" -e production
```

## Users vs Principals

It's important to understand the distinction:

| Concept | Description |
|---------|-------------|
| **User** | A person, identified by email address |
| **Principal** | A device/credential, identified by name |

One user can have multiple principals (laptop, desktop, CI system). Users exist for auditing and permissions; principals exist for authentication and key management.

```bash
# A user's principals
alice@company.com
 ├── alice-macbook (personal laptop)
 ├── alice-desktop (work machine)
 └── github-actions (CI principal)
```

## RBAC Permissions

zopp has three roles that can be assigned at workspace, project, or environment level:

| Role | Can Read | Can Write | Can Admin |
|------|----------|-----------|-----------|
| `read` | Yes | | |
| `write` | Yes | Yes | |
| `admin` | Yes | Yes | Yes |

Admin permissions include:
- Creating/deleting projects and environments
- Managing permissions for others
- Creating workspace invites

Permissions cascade down:
- Workspace `admin` → admin on all projects and environments
- Project `write` → write on all environments in that project
- Environment `read` → read only that specific environment

```bash
# Give a user read access to production only
zopp permission user-env-set -w acme-corp -p api-backend -e production \
  --email dev@company.com --role read
```

## Best Practices

1. **One workspace per organization** - Most teams only need one workspace.

2. **One project per application** - Map projects to your services/applications.

3. **Consistent environment names** - Use the same names (`development`, `staging`, `production`) across projects.

4. **Use `zopp.toml`** - Configure defaults to avoid repetitive flags.

5. **Limit production access** - Use environment-level permissions to restrict who can read production secrets.

6. **Service principals for CI** - Create dedicated principals for CI/CD with minimal permissions.

## Next Steps

- [Team Collaboration](/guides/team-collaboration) - Invite team members
- [CI/CD Integration](/guides/ci-cd) - Set up service principals
- [CLI Reference](/reference/cli) - Full command documentation
