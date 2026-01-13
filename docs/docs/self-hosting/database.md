---
sidebar_position: 3
title: Database Setup
description: Configure SQLite or PostgreSQL for zopp.
---

# Database Setup

zopp supports two database backends: SQLite for simple deployments and PostgreSQL for production.

## SQLite (Default)

SQLite is the default and requires no configuration:

```bash
# Uses default path: ./zopp.db
./zopp-server serve

# Custom path
./zopp-server serve --db /var/lib/zopp/zopp.db
```

### When to Use SQLite

- Development environments
- Small teams (< 10 users)
- Single-server deployments
- Low request volume

### SQLite Best Practices

1. **Use a dedicated directory**: `/var/lib/zopp/`
2. **Regular backups**: `sqlite3 zopp.db ".backup backup.db"`
3. **SSD storage**: SQLite benefits from fast disk I/O

## PostgreSQL (Production)

PostgreSQL is recommended for production:

```bash
# Environment variable
export DATABASE_URL=postgres://user:password@localhost:5432/zopp
./zopp-server serve

# Or as a flag
./zopp-server serve --database-url postgres://user:password@localhost:5432/zopp
```

### When to Use PostgreSQL

- Production environments
- Large teams
- High availability requirements
- Multiple server instances

### PostgreSQL Setup

1. **Create the database**:
   ```sql
   CREATE DATABASE zopp;
   CREATE USER zopp WITH PASSWORD 'your-password';
   GRANT ALL PRIVILEGES ON DATABASE zopp TO zopp;
   -- Required for PostgreSQL 15+ (public schema permissions changed)
   \c zopp
   GRANT ALL ON SCHEMA public TO zopp;
   ```

2. **Run the server**:
   ```bash
   DATABASE_URL=postgres://zopp:your-password@localhost/zopp ./zopp-server serve
   ```

Migrations run automatically on startup.

### Connection Pool

zopp uses a connection pool with sensible defaults:

| Setting | Default | Description |
|---------|---------|-------------|
| Max connections | 10 | Maximum pool size |
| Min connections | 1 | Minimum idle connections |
| Connect timeout | 30s | Connection timeout |

## Backups

### SQLite

```bash
# Simple backup
sqlite3 /var/lib/zopp/zopp.db ".backup /backup/zopp-$(date +%Y%m%d).db"

# Scheduled (cron)
0 2 * * * sqlite3 /var/lib/zopp/zopp.db ".backup /backup/zopp-$(date +\%Y\%m\%d).db"
```

### PostgreSQL

```bash
# Full backup
pg_dump -h localhost -U zopp zopp > /backup/zopp-$(date +%Y%m%d).sql

# Compressed
pg_dump -h localhost -U zopp zopp | gzip > /backup/zopp-$(date +%Y%m%d).sql.gz
```

:::caution
Never lose your database! While secrets are encrypted, the wrapped keys that allow decryption are stored there. Without the database, users cannot decrypt their secrets.
:::

## Next Steps

- [TLS Configuration](/self-hosting/tls) - Secure your deployment
- [Server Deployment](/self-hosting/server) - Deployment options
