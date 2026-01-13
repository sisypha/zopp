---
sidebar_position: 6
title: Import & Export
description: Work with .env files and migrate secrets between environments.
---

# Import & Export

zopp makes it easy to work with `.env` files and migrate secrets between environments. This guide covers importing, exporting, and common workflows.

## Exporting Secrets

Export all secrets from an environment to a `.env` file:

```bash
# Export to file
zopp secret export -o .env

# Export to stdout
zopp secret export

# Export from specific environment
zopp secret export -w myworkspace -p myproject -e production -o prod.env
```

The output format is standard `.env`:

```bash
# .env
DATABASE_URL=postgresql://user:pass@localhost/db
API_KEY=sk_live_abc123
REDIS_URL=redis://localhost:6379
```

:::danger
Exported files contain plaintext secrets. Keep them secure and never commit them to version control.
:::

### Export Options

```bash
# Export all secrets (default)
zopp secret export -o .env

# Secrets are sorted alphabetically by key
```

## Importing Secrets

Import secrets from a `.env` file:

```bash
# Import from file
zopp secret import -i .env

# Import from stdin
cat .env | zopp secret import

# Import to specific environment
zopp secret import -w myworkspace -p myproject -e production -i prod.env
```

### Supported Formats

zopp supports standard `.env` format:

```bash
# Comments are ignored
# Blank lines are ignored

SIMPLE_KEY=value
QUOTED_VALUE="value with spaces"
SINGLE_QUOTED='value with spaces'
MULTILINE="line1\nline2"

# No interpolation - ${VAR} is stored literally
LITERAL=${OTHER_VAR}
```

### Import Behavior

- **Existing keys are updated** - If a key already exists, its value is replaced
- **New keys are created** - Keys that don't exist are added
- **Keys not in file are preserved** - Import doesn't delete existing secrets

## Common Workflows

### Copy Secrets Between Environments

```bash
# Export from staging
zopp secret export -e staging -o staging.env

# Import to production
zopp secret import -e production -i staging.env
```

### Migrate from .env Files

Moving from file-based secrets to zopp:

```bash
# 1. Create the environment
zopp environment create development -w myworkspace -p myproject

# 2. Import existing .env file
zopp secret import -w myworkspace -p myproject -e development -i .env

# 3. Verify
zopp secret list -w myworkspace -p myproject -e development
```

### Seed New Environment

```bash
# Export template from development
zopp secret export -e development -o template.env

# Edit template with production values
vim template.env

# Import to production
zopp secret import -e production -i template.env
```

### Sync Local Development

```bash
# Pull latest secrets from zopp
zopp secret export -e development -o .env

# Start your application
npm start  # or docker-compose up, etc.
```

### Backup Secrets

```bash
# Export all environments
zopp secret export -e development -o backup/dev.env
zopp secret export -e staging -o backup/staging.env
zopp secret export -e production -o backup/prod.env

# Encrypt the backup
tar -czf secrets-backup.tar.gz backup/
gpg -c secrets-backup.tar.gz
rm -rf backup/ secrets-backup.tar.gz
```

## Using `zopp run`

Instead of exporting to a file, inject secrets directly into a command:

```bash
# Run with secrets as environment variables
zopp run -- npm start

# Override environment
zopp run -e production -- npm start

# One-off commands
zopp run -- printenv DATABASE_URL
```

This is more secure than exporting because secrets never touch the filesystem.

## Best Practices

### 1. Use `zopp run` When Possible

```bash
# Preferred: secrets never written to disk
zopp run -- npm start

# Avoid if possible: creates file with plaintext secrets
zopp secret export -o .env && npm start
```

### 2. Add .env to .gitignore

```bash
# .gitignore
.env
.env.*
*.env
```

### 3. Use Environment-Specific Files

```bash
# Good
zopp secret export -e development -o .env.development
zopp secret export -e production -o .env.production

# Then source the right one
source .env.development
```

### 4. Clean Up After Use

```bash
# Export, use, delete
zopp secret export -o .env
./my-script.sh
rm .env
```

Or use a subshell:

```bash
(zopp secret export -o .env && ./my-script.sh; rm -f .env)
```

### 5. Validate Before Import

```bash
# Preview what would be imported
cat .env | head -20

# Check for sensitive values you might not want to store
grep -E "TOKEN|SECRET|KEY" .env
```

## Troubleshooting

### Import Fails Silently

Make sure the file format is correct:

```bash
# Check for BOM or weird characters
file .env
hexdump -C .env | head

# Convert from Windows line endings if needed
dos2unix .env
```

### Special Characters in Values

Use quotes for values with special characters:

```bash
# Good
PASSWORD="p@ss!word#123"

# May cause issues
PASSWORD=p@ss!word#123
```

### Environment Variables Not Set

When using `zopp run`, ensure secrets are actually exported:

```bash
# Debug: print all environment variables
zopp run -- env

# Check specific variable
zopp run -- printenv DATABASE_URL
```

## Next Steps

- [CLI Reference](/zopp/reference/cli) - Full command reference
- [Core Concepts](/zopp/guides/core-concepts) - Understand the data model
