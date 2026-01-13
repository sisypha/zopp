---
sidebar_position: 5
title: secret
description: Store, retrieve, and manage encrypted secrets.
---

# secret

Store, retrieve, and manage secrets. All secrets are encrypted client-side before being sent to the server.

```bash
zopp secret <COMMAND>
```

## Commands

| Command | Description |
|---------|-------------|
| `set` | Set (create or update) a secret |
| `get` | Retrieve and decrypt a secret |
| `list` | List all secrets in an environment |
| `delete` | Delete a secret |
| `export` | Export secrets to a .env file |
| `import` | Import secrets from a .env file |

---

## secret set

Set (upsert) a secret. The value is encrypted client-side using XChaCha20-Poly1305 before being stored.

```bash
zopp secret set [OPTIONS] <KEY> <VALUE>
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `KEY` | Yes | Secret key (e.g., `DATABASE_URL`) |
| `VALUE` | Yes | Secret value (plaintext - encrypted automatically) |

### Options

| Option | Required | Description |
|--------|----------|-------------|
| `-w, --workspace <WORKSPACE>` | No | Workspace name (defaults from zopp.toml) |
| `-p, --project <PROJECT>` | No | Project name (defaults from zopp.toml) |
| `-e, --environment <ENVIRONMENT>` | No | Environment name (defaults from zopp.toml) |
| `-h, --help` | No | Print help |

### Examples

```bash
# With explicit flags
zopp secret set -w mycompany -p backend -e development DATABASE_URL "postgresql://localhost/mydb"

# With zopp.toml defaults
zopp secret set DATABASE_URL "postgresql://localhost/mydb"

# Set multiple secrets
zopp secret set API_KEY "sk-12345"
zopp secret set REDIS_URL "redis://localhost:6379"
```

---

## secret get

Retrieve and decrypt a secret.

```bash
zopp secret get [OPTIONS] <KEY>
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `KEY` | Yes | Secret key to retrieve |

### Options

| Option | Required | Description |
|--------|----------|-------------|
| `-w, --workspace <WORKSPACE>` | No | Workspace name (defaults from zopp.toml) |
| `-p, --project <PROJECT>` | No | Project name (defaults from zopp.toml) |
| `-e, --environment <ENVIRONMENT>` | No | Environment name (defaults from zopp.toml) |
| `-h, --help` | No | Print help |

### Examples

```bash
$ zopp secret get DATABASE_URL
postgresql://localhost/mydb

# Use in scripts
export DATABASE_URL=$(zopp secret get DATABASE_URL)
```

---

## secret list

List all secret keys in an environment. Only keys are shown, not values.

```bash
zopp secret list [OPTIONS]
```

### Options

| Option | Required | Description |
|--------|----------|-------------|
| `-w, --workspace <WORKSPACE>` | No | Workspace name (defaults from zopp.toml) |
| `-p, --project <PROJECT>` | No | Project name (defaults from zopp.toml) |
| `-e, --environment <ENVIRONMENT>` | No | Environment name (defaults from zopp.toml) |
| `-h, --help` | No | Print help |

### Example

```bash
$ zopp secret list
DATABASE_URL
REDIS_URL
API_KEY
JWT_SECRET
```

---

## secret delete

Delete a secret from an environment.

```bash
zopp secret delete [OPTIONS] <KEY>
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `KEY` | Yes | Secret key to delete |

### Options

| Option | Required | Description |
|--------|----------|-------------|
| `-w, --workspace <WORKSPACE>` | No | Workspace name (defaults from zopp.toml) |
| `-p, --project <PROJECT>` | No | Project name (defaults from zopp.toml) |
| `-e, --environment <ENVIRONMENT>` | No | Environment name (defaults from zopp.toml) |
| `-h, --help` | No | Print help |

### Example

```bash
$ zopp secret delete OLD_API_KEY
Secret "OLD_API_KEY" deleted
```

---

## secret export

Export all secrets from an environment to a .env file format.

```bash
zopp secret export [OPTIONS]
```

### Options

| Option | Required | Description |
|--------|----------|-------------|
| `-w, --workspace <WORKSPACE>` | No | Workspace name (defaults from zopp.toml) |
| `-p, --project <PROJECT>` | No | Project name (defaults from zopp.toml) |
| `-e, --environment <ENVIRONMENT>` | No | Environment name (defaults from zopp.toml) |
| `-o, --output <OUTPUT>` | No | Output file path (defaults to stdout) |
| `-h, --help` | No | Print help |

### Examples

```bash
# Export to file
zopp secret export -o .env

# Export to stdout
zopp secret export

# Export specific environment
zopp secret export -e production -o .env.production
```

---

## secret import

Import secrets from a .env file into an environment.

```bash
zopp secret import [OPTIONS]
```

### Options

| Option | Required | Description |
|--------|----------|-------------|
| `-w, --workspace <WORKSPACE>` | No | Workspace name (defaults from zopp.toml) |
| `-p, --project <PROJECT>` | No | Project name (defaults from zopp.toml) |
| `-e, --environment <ENVIRONMENT>` | No | Environment name (defaults from zopp.toml) |
| `-i, --input <INPUT>` | No | Input file path (defaults to stdin) |
| `-h, --help` | No | Print help |

### Examples

```bash
# Import from file
zopp secret import -i .env

# Import from stdin
cat .env | zopp secret import

# Import to specific environment
zopp secret import -e staging -i .env.staging
```
