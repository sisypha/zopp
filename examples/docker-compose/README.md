# Docker Compose Examples

Quick deployment options for zopp using Docker Compose.

## Development / Testing

Start a local zopp instance:

```bash
docker compose up -d
```

Create an invite to bootstrap the first user:

```bash
docker compose exec zopp-server zopp-server invite create --expires-hours 48
```

## Production

1. Generate TLS certificates in `./certs/`:
   ```bash
   mkdir -p certs
   # Use your CA or generate self-signed:
   openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt -days 365 -nodes -subj "/CN=zopp"
   ```

2. Set a secure database password:
   ```bash
   export POSTGRES_PASSWORD=$(openssl rand -base64 32)
   ```

3. Start the stack:
   ```bash
   docker compose -f docker-compose.production.yml up -d
   ```

4. Create an invite:
   ```bash
   docker compose -f docker-compose.production.yml exec zopp-server zopp-server invite create --expires-hours 48
   ```

## Files

- `docker-compose.yml` - Development setup (no TLS, default passwords)
- `docker-compose.production.yml` - Production setup (TLS, resource limits)
